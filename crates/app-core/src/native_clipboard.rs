//! Native clipboard authorization and per-session ownership.
//!
//! Clipboard text stays inside the SDK/platform one-shot path. This module
//! exposes only direction choices, sanitized outcomes and exact session
//! bindings to the application IPC layer.
use nestlink_platform_clipboard::{
    ClipboardAuthority, ClipboardBinding as PlatformBinding, ClipboardCleanup,
    ClipboardDirection as PlatformDirection, ClipboardMonitor, LocalClipboardApproval,
    LocalClipboardApprovalControl, NativeClipboard as PlatformClipboard,
};
use nestlink_protocol::ClipboardWriteEffect;
#[cfg(test)]
use nestlink_protocol::Permission;
use nestlink_remote::{
    ChannelRuntime, LeaseControl, RemoteError,
    clipboard::{
        ClaimedClipboardTransport, ClipboardBinding as WireBinding, ClipboardConsent,
        ClipboardDevice as RemoteClipboardDevice, ClipboardDirection as RemoteDirection,
        ClipboardDirections, ClipboardServerDeviceControl, ClipboardWriteOutcome,
    },
};
use nestlink_sdk::clipboard::{
    ClipboardEndpoint, ControllerClipboard, NativeClipboardError as SdkClipboardError,
    NativeClipboardHandle, NativeClipboardOutput, NativeClipboardOwner, NativeClipboardShutdown,
    PlatformClipboardAuthority,
};
use nestlink_session::StopReason as SessionStopReason;
use nestlink_transport_stream::Channel;
use serde::{Deserialize, Serialize};
use std::{
    io,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Mutex as AsyncMutex, task::JoinHandle};

const OWNER_SHUTDOWN_BUDGET: Duration = Duration::from_millis(100);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeClipboardBinding {
    pub request_id: String,
    pub connection_generation: u64,
    pub core_generation: u64,
}

impl NativeClipboardBinding {
    fn new(request_id: String, connection_generation: u64, core_generation: u64) -> Option<Self> {
        if request_id.is_empty()
            || request_id.len() > 128
            || connection_generation == 0
            || core_generation == 0
        {
            return None;
        }
        Some(Self {
            request_id,
            connection_generation,
            core_generation,
        })
    }

    fn matches(&self, supplied: &Self) -> bool {
        self == supplied
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeClipboardAction {
    /// Read the host clipboard and explicitly copy the result to the controller.
    CopyRemoteToLocal,
    /// Read the controller clipboard and explicitly send it to the host.
    SendLocalToRemote,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeClipboardEndpoint {
    Host,
    Controller,
}
impl From<ClipboardEndpoint> for NativeClipboardEndpoint {
    fn from(value: ClipboardEndpoint) -> Self {
        match value {
            ClipboardEndpoint::Host => Self::Host,
            ClipboardEndpoint::Controller => Self::Controller,
        }
    }
}
impl From<NativeClipboardEndpoint> for ClipboardEndpoint {
    fn from(value: NativeClipboardEndpoint) -> Self {
        match value {
            NativeClipboardEndpoint::Host => Self::Host,
            NativeClipboardEndpoint::Controller => Self::Controller,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalClipboardDirections {
    read: bool,
    write: bool,
}
impl LocalClipboardDirections {
    /// Directions always come from an explicit local choice. There is no
    /// permissive default for either OS clipboard access direction.
    pub const fn from_explicit_selections(read: bool, write: bool) -> Self {
        Self { read, write }
    }

    fn allows(self, endpoint: ClipboardEndpoint, action: NativeClipboardAction) -> bool {
        let reads_local_clipboard = matches!(
            (endpoint, action),
            (
                ClipboardEndpoint::Host,
                NativeClipboardAction::CopyRemoteToLocal
            ) | (
                ClipboardEndpoint::Controller,
                NativeClipboardAction::SendLocalToRemote
            )
        );
        if reads_local_clipboard {
            self.read
        } else {
            self.write
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClipboardPermitDirections {
    read: bool,
    write: bool,
}
impl ClipboardPermitDirections {
    #[cfg(test)]
    fn from_verified_permissions(permissions: &[Permission]) -> Self {
        Self {
            read: permissions.contains(&Permission::ClipboardRead),
            write: permissions.contains(&Permission::ClipboardWrite),
        }
    }

    fn allows(self, action: NativeClipboardAction) -> bool {
        match action {
            NativeClipboardAction::CopyRemoteToLocal => self.read,
            NativeClipboardAction::SendLocalToRemote => self.write,
        }
    }

    fn sdk_directions(self) -> ClipboardDirections {
        ClipboardDirections {
            read: self.read,
            write: self.write,
        }
    }

    fn host_has_local_direction(self, read: bool, write: bool) -> bool {
        (!read || self.read) && (!write || self.write)
    }

    fn controller_has_local_direction(self, read: bool, write: bool) -> bool {
        // Controller Read sends through ClipboardWrite. Controller Write
        // consumes ClipboardRead.
        (!read || self.write) && (!write || self.read)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NativeClipboardAuthorizationError {
    #[error("native clipboard session binding is stale")]
    StaleBinding,
    #[error("native session permit does not grant this clipboard direction")]
    PermitRequired,
    #[error("this endpoint has not approved the required clipboard direction")]
    LocalConsentRequired,
}

struct NativeClipboardPolicy {
    binding: NativeClipboardBinding,
    endpoint: ClipboardEndpoint,
    permit: ClipboardPermitDirections,
    local: LocalClipboardDirections,
}
impl NativeClipboardPolicy {
    #[cfg(test)]
    fn new(
        binding: NativeClipboardBinding,
        endpoint: ClipboardEndpoint,
        verified_permissions: &[Permission],
        local: LocalClipboardDirections,
    ) -> Self {
        Self {
            binding,
            endpoint,
            permit: ClipboardPermitDirections::from_verified_permissions(verified_permissions),
            local,
        }
    }

    fn from_permit(
        binding: NativeClipboardBinding,
        endpoint: ClipboardEndpoint,
        permit: ClipboardPermitDirections,
        local: LocalClipboardDirections,
    ) -> Self {
        Self {
            binding,
            endpoint,
            permit,
            local,
        }
    }

    fn authorize(
        &self,
        supplied: &NativeClipboardBinding,
        action: NativeClipboardAction,
    ) -> Result<(), NativeClipboardAuthorizationError> {
        if !self.binding.matches(supplied) {
            return Err(NativeClipboardAuthorizationError::StaleBinding);
        }
        if !self.permit.allows(action) {
            return Err(NativeClipboardAuthorizationError::PermitRequired);
        }
        if !self.local.allows(self.endpoint, action) {
            return Err(NativeClipboardAuthorizationError::LocalConsentRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeClipboardEffect {
    Applied,
    NotApplied,
    Unknown,
}
impl From<ClipboardWriteEffect> for NativeClipboardEffect {
    fn from(value: ClipboardWriteEffect) -> Self {
        match value {
            ClipboardWriteEffect::ClipboardWriteApplied => Self::Applied,
            ClipboardWriteEffect::ClipboardWriteNotApplied => Self::NotApplied,
            ClipboardWriteEffect::ClipboardWriteUnknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeClipboardStatus {
    pub binding: NativeClipboardBinding,
    pub endpoint: NativeClipboardEndpoint,
    pub permitted_read: bool,
    pub permitted_write: bool,
    pub local_read: bool,
    pub local_write: bool,
    pub ready: bool,
    pub session_restart_required: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum NativeClipboardError {
    #[error("native clipboard session binding is stale")]
    StaleBinding,
    #[error("native clipboard session or permission is unavailable")]
    Unauthorized,
    #[error("the local OS clipboard direction was not selected")]
    LocalConsentRequired,
    #[error("the selected clipboard direction needs a new native session")]
    ReestablishSession,
    #[error("local clipboard support is unavailable ({0:?})")]
    PlatformUnavailable(io::ErrorKind),
    #[error("clipboard transport failed")]
    Transport,
    #[error("clipboard owner stopped")]
    Stopped,
    #[error("clipboard cleanup could not be confirmed")]
    Cleanup,
}

impl From<NativeClipboardAuthorizationError> for NativeClipboardError {
    fn from(value: NativeClipboardAuthorizationError) -> Self {
        match value {
            NativeClipboardAuthorizationError::StaleBinding => Self::StaleBinding,
            NativeClipboardAuthorizationError::PermitRequired => Self::Unauthorized,
            NativeClipboardAuthorizationError::LocalConsentRequired => Self::LocalConsentRequired,
        }
    }
}

/// Platform adapter construction is injected by the unprivileged daemon. It
/// receives a one-use approval created only after a local IPC selection.
pub trait NativeClipboardPlatformFactory: Send + Sync + 'static {
    fn open(
        &self,
        binding: PlatformBinding,
        core_generation: u64,
        approval: LocalClipboardApproval,
        authority: Arc<dyn ClipboardAuthority>,
    ) -> io::Result<Box<dyn PlatformClipboard>>;
}

struct BoxedPlatformClipboard(Box<dyn PlatformClipboard>);
impl PlatformClipboard for BoxedPlatformClipboard {
    fn binding(&self) -> &PlatformBinding {
        self.0.binding()
    }
    fn monitor(&self) -> ClipboardMonitor {
        self.0.monitor()
    }
    fn direction_guard(
        &self,
        direction: PlatformDirection,
    ) -> nestlink_platform_clipboard::ClipboardDirectionGuard {
        self.0.direction_guard(direction)
    }
    fn check(&mut self) -> io::Result<()> {
        self.0.check()
    }
    fn read_text(&mut self) -> io::Result<Option<String>> {
        self.0.read_text()
    }
    fn write_text(&mut self, text: &str) -> io::Result<()> {
        self.0.write_text(text)
    }
    fn close(&mut self) -> io::Result<()> {
        self.0.close()
    }
}

struct PlatformDirectionConsent(nestlink_platform_clipboard::ClipboardDirectionGuard);
impl ClipboardConsent for PlatformDirectionConsent {
    fn check_until(&self, deadline: std::time::Instant) -> io::Result<()> {
        self.0.check_until(deadline)
    }
}

struct HostPlatformClipboardDevice {
    binding: WireBinding,
    native: BoxedPlatformClipboard,
}
impl RemoteClipboardDevice for HostPlatformClipboardDevice {
    fn binding(&self) -> &WireBinding {
        &self.binding
    }

    fn consent(&self, direction: RemoteDirection) -> Arc<dyn ClipboardConsent> {
        Arc::new(PlatformDirectionConsent(self.native.direction_guard(
            match direction {
                RemoteDirection::Read => PlatformDirection::Read,
                RemoteDirection::Write => PlatformDirection::Write,
            },
        )))
    }

    fn read_text(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        authorized()?;
        let text = self.native.read_text()?.map(zeroize::Zeroizing::new);
        authorized()?;
        Ok(text.map(|mut text| std::mem::take(&mut *text)))
    }

    fn write_text(
        &mut self,
        text: &str,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> ClipboardWriteOutcome {
        if let Err(error) = authorized() {
            return ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteNotApplied,
                error: Some(error),
            };
        }
        match self.native.write_text(text) {
            Ok(()) => ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteApplied,
                error: authorized().err(),
            },
            Err(error) => ClipboardWriteOutcome {
                effect: ClipboardWriteEffect::ClipboardWriteUnknown,
                error: Some(error),
            },
        }
    }

    fn close(&mut self) -> io::Result<()> {
        self.native.close()
    }

    fn cleanup_complete(&self) -> bool {
        matches!(
            self.native.monitor().status().cleanup,
            ClipboardCleanup::Complete
        )
    }
}

struct DirectionConsent {
    route: Weak<NativeClipboardRoute>,
    binding: NativeClipboardBinding,
    action: NativeClipboardAction,
}
impl ClipboardConsent for DirectionConsent {
    fn check_until(&self, deadline: std::time::Instant) -> io::Result<()> {
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "clipboard action expired",
            ));
        }
        let route = self.route.upgrade().ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "clipboard route ended")
        })?;
        route.authorize(&self.binding, self.action).map_err(|_| {
            io::Error::new(io::ErrorKind::PermissionDenied, "clipboard action revoked")
        })
    }
}

enum ClipboardOwner {
    Host(nestlink_remote::clipboard::ClipboardServer),
    Controller(NativeClipboardOwner),
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct NativeClipboardShutdownReport {
    pub cleanup_failed: bool,
    pub worker_failed: bool,
    pub owner_pending: bool,
}
#[derive(Default)]
struct ShutdownState {
    outcome: Option<NativeClipboardShutdownReport>,
}
struct SelectionState {
    read: bool,
    write: bool,
    approval: Option<LocalClipboardApprovalControl>,
    monitor: Option<ClipboardMonitor>,
    session_restart_required: bool,
}

/// Owns every permitted clipboard claim for one proved session. Local OS
/// access starts only after an authenticated, explicit direction selection.
pub(super) struct NativeClipboardRoute {
    binding: NativeClipboardBinding,
    endpoint: ClipboardEndpoint,
    permit: ClipboardPermitDirections,
    wire_binding: WireBinding,
    lease: LeaseControl,
    shared: Weak<super::Shared>,
    active: AtomicBool,
    current_core_generation: Arc<std::sync::atomic::AtomicU64>,
    claims: Mutex<Option<ClaimedClipboardTransport>>,
    host_device: Option<ClipboardServerDeviceControl>,
    orphaned_platforms: Arc<Mutex<Vec<BoxedPlatformClipboard>>>,
    owner: AsyncMutex<Option<ClipboardOwner>>,
    activation: AsyncMutex<()>,
    selection: Mutex<SelectionState>,
    controller: Arc<Mutex<Option<ControllerClipboard<BoxedPlatformClipboard>>>>,
    controller_handle: Mutex<Option<NativeClipboardHandle>>,
    operations: AsyncMutex<()>,
    shutdown: AsyncMutex<ShutdownState>,
    reaper: Mutex<Option<JoinHandle<NativeClipboardShutdownReport>>>,
}

impl NativeClipboardRoute {
    pub(super) fn attach(
        shared: &Arc<super::Shared>,
        channels: &mut ChannelRuntime,
        key: &super::NativeSessionKey,
        generation: u64,
    ) -> Result<Arc<Self>, RemoteError> {
        let permit = ClipboardDirections {
            read: key.clipboard_read_authorized,
            write: key.clipboard_write_authorized,
        };
        if !permit.read && !permit.write {
            return Err(
                io::Error::new(io::ErrorKind::PermissionDenied, "no clipboard permit").into(),
            );
        }
        let lease = channels.lease_control();
        let binding_channel = if permit.read {
            Channel::ClipboardRead
        } else {
            Channel::ClipboardWrite
        };
        let session_id = lease.clipboard_session_id(binding_channel, key.connection_generation)?;
        let claimed_binding = WireBinding {
            session_id,
            connection_generation: key.connection_generation,
        };
        let transport =
            ClaimedClipboardTransport::claim(channels, claimed_binding.clone(), permit)?;
        let binding = NativeClipboardBinding::new(
            key.request_id.clone(),
            key.connection_generation,
            generation,
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid clipboard binding"))?;
        let endpoint = if key.is_host {
            ClipboardEndpoint::Host
        } else {
            ClipboardEndpoint::Controller
        };
        let (claims, initial_owner, host_device) = match endpoint {
            ClipboardEndpoint::Host => {
                let (server, control) =
                    nestlink_remote::clipboard::ClipboardServer::start_claimed_switchable(
                        transport, permit,
                    )?;
                (None, Some(ClipboardOwner::Host(server)), Some(control))
            }
            ClipboardEndpoint::Controller => (Some(transport), None, None),
        };
        Ok(Arc::new(Self {
            binding,
            endpoint,
            permit: ClipboardPermitDirections {
                read: permit.read,
                write: permit.write,
            },
            wire_binding: claimed_binding,
            lease,
            shared: Arc::downgrade(shared),
            active: AtomicBool::new(true),
            current_core_generation: shared.generation.clone(),
            claims: Mutex::new(claims),
            host_device,
            orphaned_platforms: Arc::new(Mutex::new(Vec::new())),
            owner: AsyncMutex::new(initial_owner),
            activation: AsyncMutex::new(()),
            selection: Mutex::new(SelectionState {
                read: false,
                write: false,
                approval: None,
                monitor: None,
                session_restart_required: false,
            }),
            controller: Arc::new(Mutex::new(None)),
            controller_handle: Mutex::new(None),
            operations: AsyncMutex::new(()),
            shutdown: AsyncMutex::new(ShutdownState::default()),
            reaper: Mutex::new(None),
        }))
    }

    fn live(&self) -> Result<(), NativeClipboardError> {
        if !self.active.load(Ordering::Acquire)
            || self.current_core_generation.load(Ordering::Acquire) != self.binding.core_generation
        {
            return Err(NativeClipboardError::StaleBinding);
        }
        let channel = if self.permit.read {
            Channel::ClipboardRead
        } else {
            Channel::ClipboardWrite
        };
        self.lease
            .check_clipboard_binding(
                &self.binding.request_id,
                channel,
                self.binding.connection_generation,
            )
            .map_err(|_| NativeClipboardError::Unauthorized)
    }

    fn authorize(
        &self,
        supplied: &NativeClipboardBinding,
        action: NativeClipboardAction,
    ) -> Result<(), NativeClipboardError> {
        self.live()?;
        if !self.binding.matches(supplied) {
            return Err(NativeClipboardError::StaleBinding);
        }
        let selection = self
            .selection
            .lock()
            .map_err(|_| NativeClipboardError::Stopped)?;
        NativeClipboardPolicy::from_permit(
            self.binding.clone(),
            self.endpoint,
            self.permit,
            LocalClipboardDirections::from_explicit_selections(selection.read, selection.write),
        )
        .authorize(supplied, action)
        .map_err(Into::into)
    }

    fn status(&self) -> NativeClipboardStatus {
        let selection = self
            .selection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        NativeClipboardStatus {
            binding: self.binding.clone(),
            endpoint: self.endpoint.into(),
            permitted_read: self.permit.read,
            permitted_write: self.permit.write,
            local_read: selection.read,
            local_write: selection.write,
            ready: selection.approval.is_some(),
            session_restart_required: selection.session_restart_required,
        }
    }

    fn platform_binding(&self) -> PlatformBinding {
        PlatformBinding {
            session_id: self.binding.request_id.clone(),
            connection_generation: self.binding.connection_generation,
        }
    }

    fn close_or_retain_platform(&self, platform: Box<dyn PlatformClipboard>) {
        self.close_or_retain_boxed_platform(BoxedPlatformClipboard(platform));
    }

    fn close_or_retain_boxed_platform(&self, mut platform: BoxedPlatformClipboard) {
        let monitor = platform.monitor();
        let _ = platform.close();
        if !matches!(monitor.status().cleanup, ClipboardCleanup::Complete) {
            let mut pending = self
                .orphaned_platforms
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.push(platform);
        }
    }

    async fn set_directions(
        self: &Arc<Self>,
        supplied: &NativeClipboardBinding,
        read: bool,
        write: bool,
    ) -> Result<NativeClipboardStatus, NativeClipboardError> {
        self.live()?;
        if !self.binding.matches(supplied) {
            return Err(NativeClipboardError::StaleBinding);
        }
        let _activation = self.activation.lock().await;
        self.live()?;
        if (matches!(self.endpoint, ClipboardEndpoint::Host)
            && !self.permit.host_has_local_direction(read, write))
            || (matches!(self.endpoint, ClipboardEndpoint::Controller)
                && !self.permit.controller_has_local_direction(read, write))
        {
            return Err(NativeClipboardError::Unauthorized);
        }
        let (started, old_read, old_write) = {
            let selection = self
                .selection
                .lock()
                .map_err(|_| NativeClipboardError::Stopped)?;
            (
                selection.approval.is_some(),
                selection.read,
                selection.write,
            )
        };
        if started {
            if (read && !old_read) || (write && !old_write) {
                if let Ok(mut selection) = self.selection.lock() {
                    selection.session_restart_required = true;
                }
                return Err(NativeClipboardError::ReestablishSession);
            }
            if matches!(self.endpoint, ClipboardEndpoint::Host)
                && let Some(device) = self.host_device.as_ref()
            {
                device.revoke(old_read && !read, old_write && !write);
            }
            if let Ok(mut selection) = self.selection.lock() {
                if old_read
                    && !read
                    && let Some(control) = selection.approval.as_ref()
                {
                    control.revoke_read();
                }
                if old_write
                    && !write
                    && let Some(control) = selection.approval.as_ref()
                {
                    control.revoke_write();
                }
                selection.read = read;
                selection.write = write;
            }
            self.live()?;
            return Ok(self.status());
        }
        if !read && !write {
            return Ok(self.status());
        }
        // The controller attach path must not yield after it has opened an
        // OS adapter or consumed the claimed transport. Acquire the owner
        // lock first so cancellation cannot drop either resource while
        // suspended on an async mutex.
        let mut controller_owner = if matches!(self.endpoint, ClipboardEndpoint::Controller) {
            let owner = self.owner.lock().await;
            if owner.is_some() {
                return Err(NativeClipboardError::ReestablishSession);
            }
            Some(owner)
        } else {
            None
        };
        let shared = self.shared.upgrade().ok_or(NativeClipboardError::Stopped)?;
        let factory = shared
            .native_clipboard_factory
            .lock()
            .map_err(|_| NativeClipboardError::Stopped)?
            .clone()
            .ok_or(NativeClipboardError::PlatformUnavailable(
                io::ErrorKind::Unsupported,
            ))?;
        let (approval, control) =
            LocalClipboardApproval::approve_from_local_user(self.platform_binding(), read, write)
                .map_err(|error| NativeClipboardError::PlatformUnavailable(error.kind()))?;
        let authority: Arc<dyn ClipboardAuthority> = Arc::new(PlatformClipboardAuthority::new(
            self.lease.clone(),
            self.endpoint,
        ));
        let mut platform = factory
            .open(
                self.platform_binding(),
                self.binding.core_generation,
                approval,
                authority,
            )
            .map_err(|error| NativeClipboardError::PlatformUnavailable(error.kind()))?;
        if let Err(error) = self.live() {
            control.revoke_all();
            self.close_or_retain_platform(platform);
            return Err(error);
        }
        if platform.binding() != &self.platform_binding()
            || self.platform_binding().session_id != self.wire_binding.session_id
            || self.platform_binding().connection_generation
                != self.wire_binding.connection_generation
        {
            control.revoke_all();
            self.close_or_retain_platform(platform);
            return Err(NativeClipboardError::StaleBinding);
        }
        if let Err(error) = platform.check() {
            control.revoke_all();
            self.close_or_retain_platform(platform);
            return Err(NativeClipboardError::PlatformUnavailable(error.kind()));
        }
        let monitor = platform.monitor();
        let platform = BoxedPlatformClipboard(platform);
        match self.endpoint {
            ClipboardEndpoint::Host => {
                let Some(device) = self.host_device.as_ref() else {
                    self.close_or_retain_boxed_platform(platform);
                    return Err(NativeClipboardError::Transport);
                };
                device
                    .install(
                        HostPlatformClipboardDevice {
                            binding: self.wire_binding.clone(),
                            native: platform,
                        },
                        ClipboardDirections { read, write },
                    )
                    .map_err(|_| NativeClipboardError::Transport)?;
            }
            ClipboardEndpoint::Controller => {
                let Some(owner) = controller_owner.as_mut() else {
                    self.close_or_retain_boxed_platform(platform);
                    return Err(NativeClipboardError::Transport);
                };
                let transport = match self.claims.lock() {
                    Ok(mut claims) => claims.take(),
                    Err(_) => {
                        self.close_or_retain_boxed_platform(platform);
                        return Err(NativeClipboardError::Stopped);
                    }
                };
                let Some(transport) = transport else {
                    self.close_or_retain_boxed_platform(platform);
                    return Err(NativeClipboardError::ReestablishSession);
                };
                let sdk_owner = match NativeClipboardOwner::attach_claimed(
                    transport,
                    self.permit.sdk_directions(),
                ) {
                    Ok(owner) => owner,
                    Err(_) => {
                        self.close_or_retain_boxed_platform(platform);
                        return Err(NativeClipboardError::Transport);
                    }
                };
                let handle = sdk_owner.handle();
                let mut controller = match self.controller.lock() {
                    Ok(controller) => controller,
                    Err(_) => {
                        self.close_or_retain_boxed_platform(platform);
                        return Err(NativeClipboardError::Stopped);
                    }
                };
                let mut controller_handle = match self.controller_handle.lock() {
                    Ok(handle) => handle,
                    Err(_) => {
                        self.close_or_retain_boxed_platform(platform);
                        return Err(NativeClipboardError::Stopped);
                    }
                };
                *controller = Some(ControllerClipboard::new(platform));
                *controller_handle = Some(handle);
                **owner = Some(ClipboardOwner::Controller(sdk_owner));
            }
        }
        drop(controller_owner);
        let mut selection = self
            .selection
            .lock()
            .map_err(|_| NativeClipboardError::Stopped)?;
        selection.read = read;
        selection.write = write;
        selection.approval = Some(control);
        selection.monitor = Some(monitor);
        drop(selection);
        if let Err(error) = self.live() {
            self.retire();
            return Err(error);
        }
        Ok(NativeClipboardStatus {
            binding: self.binding.clone(),
            endpoint: self.endpoint.into(),
            permitted_read: self.permit.read,
            permitted_write: self.permit.write,
            local_read: read,
            local_write: write,
            ready: true,
            session_restart_required: false,
        })
    }

    async fn action(
        self: &Arc<Self>,
        supplied: &NativeClipboardBinding,
        action: NativeClipboardAction,
    ) -> Result<NativeClipboardEffect, NativeClipboardError> {
        self.authorize(supplied, action)?;
        if !matches!(self.endpoint, ClipboardEndpoint::Controller) {
            return Err(NativeClipboardError::Unauthorized);
        }
        let _operation = self.operations.lock().await;
        self.authorize(supplied, action)?;
        let handle = self
            .controller_handle
            .lock()
            .map_err(|_| NativeClipboardError::Stopped)?
            .clone()
            .ok_or(NativeClipboardError::LocalConsentRequired)?;
        let route = self.clone();
        match action {
            NativeClipboardAction::CopyRemoteToLocal => {
                let consent: Arc<dyn ClipboardConsent> = Arc::new(DirectionConsent {
                    route: Arc::downgrade(self),
                    binding: self.binding.clone(),
                    action,
                });
                let ticket = handle
                    .read_remote_with_consent(consent)
                    .map_err(map_sdk_error)?;
                let completion = ticket
                    .wait()
                    .await
                    .map_err(|_| NativeClipboardError::Stopped)?;
                let text = match completion.result {
                    Ok(NativeClipboardOutput::Text(text)) => text,
                    Ok(NativeClipboardOutput::Written) => {
                        return Err(NativeClipboardError::Transport);
                    }
                    Err(error) => return Err(map_sdk_error(error)),
                };
                route.authorize(supplied, action)?;
                let controller = self.controller.clone();
                let effect = tokio::task::spawn_blocking(move || {
                    let mut controller = controller
                        .lock()
                        .map_err(|_| NativeClipboardError::Stopped)?;
                    let controller = controller.as_mut().ok_or(NativeClipboardError::Stopped)?;
                    controller
                        .apply_remote(text)
                        .map(NativeClipboardEffect::from)
                        .map_err(map_sdk_error)
                })
                .await
                .map_err(|_| NativeClipboardError::Transport)??;
                Ok(effect)
            }
            NativeClipboardAction::SendLocalToRemote => {
                let controller = self.controller.clone();
                let payload = tokio::task::spawn_blocking(move || {
                    let mut controller = controller
                        .lock()
                        .map_err(|_| NativeClipboardError::Stopped)?;
                    let controller = controller.as_mut().ok_or(NativeClipboardError::Stopped)?;
                    controller.capture_for_remote().map_err(map_sdk_error)
                })
                .await
                .map_err(|_| NativeClipboardError::Transport)??;
                route.authorize(supplied, action)?;
                let ticket = handle.send(payload).map_err(map_sdk_error)?;
                let completion = ticket
                    .wait()
                    .await
                    .map_err(|_| NativeClipboardError::Stopped)?;
                match completion.result {
                    Ok(NativeClipboardOutput::Written) => Ok(completion.write_effect.into()),
                    Ok(NativeClipboardOutput::Text(_)) => Err(NativeClipboardError::Transport),
                    Err(error) => Err(map_sdk_error(error)),
                }
            }
        }
    }

    pub(super) fn retire(&self) {
        self.active.store(false, Ordering::Release);
        if let Some(device) = self.host_device.as_ref() {
            device.revoke_all();
        }
        if let Ok(mut selection) = self.selection.lock()
            && let Some(control) = selection.approval.take()
        {
            control.revoke_all();
        }
        if let Ok(mut claims) = self.claims.lock() {
            claims.take();
        }
        if let Ok(owner) = self.owner.try_lock() {
            match owner.as_ref() {
                Some(ClipboardOwner::Host(server)) => {
                    let _ = server.monitor();
                }
                Some(ClipboardOwner::Controller(owner)) => owner.request_shutdown(),
                None => {}
            }
        }
    }

    pub(super) async fn shutdown(
        self: &Arc<Self>,
        reason: SessionStopReason,
    ) -> NativeClipboardShutdownReport {
        self.retire();
        let mut shutdown = self.shutdown.lock().await;
        if let Some(outcome) = shutdown.outcome {
            return outcome;
        }
        let mut report = NativeClipboardShutdownReport::default();
        let mut owner = self.owner.lock().await;
        match owner.as_mut() {
            Some(ClipboardOwner::Host(server)) => {
                let monitor = server.monitor();
                match server.shutdown(reason).await {
                    Ok(nestlink_remote::clipboard::ClipboardShutdown::Finished) => {
                        let status = monitor.status();
                        report.worker_failed = status.error.is_some();
                        report.cleanup_failed =
                            status.cleanup_error.is_some() || status.cleanup_timed_out;
                        owner.take();
                        report.owner_pending =
                            self.host_device_pending() || self.orphaned_platform_pending();
                    }
                    Ok(nestlink_remote::clipboard::ClipboardShutdown::Pending) => {
                        report.owner_pending = true;
                    }
                    Err(_) => {
                        report.cleanup_failed = true;
                        report.owner_pending = true;
                    }
                }
            }
            Some(ClipboardOwner::Controller(sdk_owner)) => {
                match sdk_owner.shutdown(OWNER_SHUTDOWN_BUDGET).await {
                    NativeClipboardShutdown::Complete => {
                        owner.take();
                        if self.close_controller_device().await.is_err() {
                            report.cleanup_failed = true;
                            report.owner_pending = self.controller_device_pending()
                                || self.orphaned_platform_pending();
                        }
                    }
                    NativeClipboardShutdown::Pending => report.owner_pending = true,
                    NativeClipboardShutdown::Failed => {
                        owner.take();
                        report.worker_failed = true;
                        report.cleanup_failed = true;
                        if self.close_controller_device().await.is_err() {
                            report.owner_pending = self.controller_device_pending()
                                || self.orphaned_platform_pending();
                        }
                    }
                }
            }
            None => {
                if self.host_device_pending() && self.close_host_device().await.is_err() {
                    report.cleanup_failed = true;
                    report.owner_pending = self.host_device_pending();
                }
                if self.orphaned_platform_pending()
                    && self.close_orphaned_platforms().await.is_err()
                {
                    report.cleanup_failed = true;
                    report.owner_pending |= self.orphaned_platform_pending();
                }
                if self.controller_device_pending() && self.close_controller_device().await.is_err()
                {
                    report.owner_pending = self.controller_device_pending();
                    report.cleanup_failed = true;
                }
            }
        }
        if report.owner_pending {
            return report;
        }
        if let Some(monitor) = self
            .selection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .monitor
            .as_ref()
        {
            let status = monitor.status();
            report.cleanup_failed |= matches!(status.cleanup, ClipboardCleanup::Failed(_));
            report.owner_pending |= !matches!(status.cleanup, ClipboardCleanup::Complete);
            report.worker_failed |= status.failure.is_some();
        }
        if !report.owner_pending {
            shutdown.outcome = Some(report);
        }
        report
    }

    async fn close_controller_device(&self) -> Result<(), NativeClipboardError> {
        let controller = self.controller.clone();
        let monitor = self
            .selection
            .lock()
            .map_err(|_| NativeClipboardError::Stopped)?
            .monitor
            .clone();
        tokio::task::spawn_blocking(move || {
            let mut current = controller
                .lock()
                .map_err(|_| NativeClipboardError::Stopped)?;
            let Some(owner) = current.as_mut() else {
                return Ok(());
            };
            let result = owner.close();
            let cleanup_complete = monitor.as_ref().is_some_and(|monitor| {
                matches!(monitor.status().cleanup, ClipboardCleanup::Complete)
            });
            if cleanup_complete {
                current.take();
            }
            if result.is_err() || !cleanup_complete {
                Err(NativeClipboardError::Cleanup)
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|_| NativeClipboardError::Transport)?
    }

    fn controller_device_pending(&self) -> bool {
        self.controller
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|_| {
                self.selection
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .monitor
                    .as_ref()
                    .is_some_and(|monitor| {
                        !matches!(monitor.status().cleanup, ClipboardCleanup::Complete)
                    })
            })
    }

    async fn close_host_device(&self) -> Result<(), NativeClipboardError> {
        let Some(device) = self.host_device.as_ref().cloned() else {
            return Ok(());
        };
        tokio::task::spawn_blocking(move || {
            device
                .close_device()
                .map_err(|_| NativeClipboardError::Cleanup)
        })
        .await
        .map_err(|_| NativeClipboardError::Transport)?
    }

    fn host_device_pending(&self) -> bool {
        self.host_device
            .as_ref()
            .is_some_and(ClipboardServerDeviceControl::cleanup_pending)
    }

    async fn close_orphaned_platforms(&self) -> Result<(), NativeClipboardError> {
        let platforms = self.orphaned_platforms.clone();
        tokio::task::spawn_blocking(move || {
            let mut platforms = platforms
                .lock()
                .map_err(|_| NativeClipboardError::Stopped)?;
            let mut retained = Vec::new();
            let mut cleanup_failed = false;
            for mut platform in std::mem::take(&mut *platforms) {
                let monitor = platform.monitor();
                let result = platform.close();
                if !matches!(monitor.status().cleanup, ClipboardCleanup::Complete) {
                    retained.push(platform);
                    cleanup_failed = true;
                } else if result.is_err() {
                    cleanup_failed = true;
                }
            }
            *platforms = retained;
            if cleanup_failed {
                Err(NativeClipboardError::Cleanup)
            } else {
                Ok(())
            }
        })
        .await
        .map_err(|_| NativeClipboardError::Transport)?
    }

    fn orphaned_platform_pending(&self) -> bool {
        self.orphaned_platforms
            .lock()
            .map(|platforms| {
                platforms.iter().any(|platform| {
                    !matches!(
                        platform.monitor().status().cleanup,
                        ClipboardCleanup::Complete
                    )
                })
            })
            .unwrap_or(true)
    }

    fn has_pending_owner(&self) -> bool {
        let owner_pending = self
            .owner
            .try_lock()
            .map(|owner| owner.is_some())
            .unwrap_or(true);
        owner_pending
            || self.host_device_pending()
            || self.orphaned_platform_pending()
            || self.controller_device_pending()
    }

    fn reap_finished_owner(self: &Arc<Self>) {
        let mut reaper = self
            .reaper
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if reaper.as_ref().is_some_and(JoinHandle::is_finished) {
            reaper.take();
        }
        if reaper.is_some() || !self.has_pending_owner() {
            return;
        }
        let route = self.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            *reaper = Some(
                runtime.spawn(async move { route.shutdown(SessionStopReason::ExplicitExit).await }),
            );
        }
    }
}

fn map_sdk_error(error: SdkClipboardError) -> NativeClipboardError {
    match error {
        SdkClipboardError::Stopped | SdkClipboardError::Cancelled { .. } => {
            NativeClipboardError::Stopped
        }
        SdkClipboardError::Capacity | SdkClipboardError::Unselected => {
            NativeClipboardError::LocalConsentRequired
        }
        SdkClipboardError::Stale | SdkClipboardError::Authorization { .. } => {
            NativeClipboardError::Unauthorized
        }
        SdkClipboardError::Refused { .. } => NativeClipboardError::Unauthorized,
        SdkClipboardError::Transport(_) => NativeClipboardError::Transport,
        SdkClipboardError::Cleanup(_) => NativeClipboardError::Cleanup,
    }
}

impl super::Shared {
    pub(super) fn native_clipboard_route(&self) -> Option<Arc<NativeClipboardRoute>> {
        self.native_clipboard
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(super) fn set_native_clipboard_route(&self, route: Option<Arc<NativeClipboardRoute>>) {
        let previous = {
            let mut current = self
                .native_clipboard
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut *current, route)
        };
        if let Some(previous) = previous {
            previous.retire();
        }
        self.reap_native_clipboard_owners();
    }

    pub(super) fn retain_native_clipboard_owner(&self, route: Arc<NativeClipboardRoute>) {
        route.reap_finished_owner();
        if !route.has_pending_owner() {
            return;
        }
        let mut owners = self
            .native_clipboard_owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        owners.retain(|owner| {
            owner.reap_finished_owner();
            owner.has_pending_owner()
        });
        if !owners.iter().any(|owner| Arc::ptr_eq(owner, &route)) {
            owners.push(route);
        }
    }

    pub(super) fn reap_native_clipboard_owners(&self) {
        self.native_clipboard_owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|owner| {
                owner.reap_finished_owner();
                owner.has_pending_owner()
            });
    }

    pub(super) fn native_clipboard_cleanup_pending(&self) -> bool {
        self.reap_native_clipboard_owners();
        !self
            .native_clipboard_owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }
}

impl super::CoreHandle {
    pub fn install_native_clipboard_platform_factory(
        &self,
        factory: Arc<dyn NativeClipboardPlatformFactory>,
    ) -> Result<(), NativeClipboardError> {
        if self.shared.closing.load(Ordering::Acquire) {
            return Err(NativeClipboardError::Stopped);
        }
        *self
            .shared
            .native_clipboard_factory
            .lock()
            .map_err(|_| NativeClipboardError::Stopped)? = Some(factory);
        Ok(())
    }

    pub fn native_clipboard_status(&self) -> Option<NativeClipboardStatus> {
        let route = self.shared.native_clipboard_route()?;
        route.live().ok()?;
        Some(route.status())
    }

    pub async fn set_native_clipboard_directions(
        &self,
        binding: &NativeClipboardBinding,
        read: bool,
        write: bool,
    ) -> Result<NativeClipboardStatus, NativeClipboardError> {
        let route = self
            .shared
            .native_clipboard_route()
            .ok_or(NativeClipboardError::Unauthorized)?;
        route.set_directions(binding, read, write).await
    }

    pub async fn native_clipboard_action(
        &self,
        binding: &NativeClipboardBinding,
        action: NativeClipboardAction,
    ) -> Result<NativeClipboardEffect, NativeClipboardError> {
        let route = self
            .shared
            .native_clipboard_route()
            .ok_or(NativeClipboardError::Unauthorized)?;
        route.action(binding, action).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(core_generation: u64) -> NativeClipboardBinding {
        NativeClipboardBinding {
            request_id: "request-1".to_owned(),
            connection_generation: 7,
            core_generation,
        }
    }
    fn local(read: bool, write: bool) -> LocalClipboardDirections {
        LocalClipboardDirections::from_explicit_selections(read, write)
    }

    #[test]
    fn binding_requires_request_connection_and_core_generation_match() {
        let expected = binding(3);
        let policy = NativeClipboardPolicy::new(
            expected,
            ClipboardEndpoint::Controller,
            &[Permission::ClipboardRead, Permission::ClipboardWrite],
            local(true, true),
        );
        assert!(
            policy
                .authorize(&binding(3), NativeClipboardAction::CopyRemoteToLocal)
                .is_ok()
        );
        assert_eq!(
            policy.authorize(&binding(4), NativeClipboardAction::CopyRemoteToLocal),
            Err(NativeClipboardAuthorizationError::StaleBinding)
        );
    }

    #[test]
    fn local_platform_directions_are_separate_from_remote_permits() {
        let binding = binding(3);
        let policy = NativeClipboardPolicy::new(
            binding.clone(),
            ClipboardEndpoint::Controller,
            &[Permission::ClipboardRead],
            local(true, true),
        );
        assert!(
            policy
                .authorize(&binding, NativeClipboardAction::CopyRemoteToLocal)
                .is_ok()
        );
        assert_eq!(
            policy.authorize(&binding, NativeClipboardAction::SendLocalToRemote),
            Err(NativeClipboardAuthorizationError::PermitRequired)
        );

        let host = ClipboardPermitDirections {
            read: true,
            write: false,
        };
        assert!(host.host_has_local_direction(true, false));
        assert!(!host.host_has_local_direction(false, true));
        let controller = ClipboardPermitDirections {
            read: false,
            write: true,
        };
        assert!(controller.controller_has_local_direction(true, false));
        assert!(!controller.controller_has_local_direction(false, true));
    }

    #[test]
    fn no_direction_is_selected_by_default() {
        let local = local(false, false);
        assert!(!local.read);
        assert!(!local.write);
    }
}
