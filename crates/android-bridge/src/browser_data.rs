//! Android local approvals for the exact, mutually proved browser endpoint.
//! SAF storage and clipboard workers remain owned until their actual joins.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]
use crate::{
    host_files::{AndroidBrowserFileOwner, AndroidHostFiles},
    platform_clipboard::AndroidBrowserClipboardFactory,
};
use nestlink_app_core::{
    BrowserHostBinding, BrowserHostDataView, BrowserHostError, CoreHandle, browser_host_binding,
};
use nestlink_identity::VerifiedPermit;
use nestlink_platform_clipboard::{
    ClipboardAuthority, ClipboardBinding as PlatformBinding,
    ClipboardDirection as PlatformDirection, LocalClipboardApproval, LocalClipboardApprovalControl,
    NativeClipboard,
};
use nestlink_protocol::{ClipboardWriteEffect, Permission};
use nestlink_remote::{
    LeaseControl, RemoteError,
    clipboard::{
        ClipboardBinding as WireBinding, ClipboardConsent, ClipboardDevice, ClipboardDirection,
        ClipboardDirections, ClipboardServer, ClipboardServerDeviceControl, ClipboardShutdown,
        ClipboardWriteOutcome,
    },
};
use nestlink_sdk::webrtc_host::{HostDataClaims, HostDataFactory, HostDataOwner, WebRtcHostError};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Android browser data approval ended",
    )
}
fn local_error(_: impl std::fmt::Display) -> String {
    "Android browser data operation is unavailable for this exact session".to_owned()
}

#[derive(Clone, Copy)]
struct Permitted {
    file_read: bool,
    file_write: bool,
    clipboard: ClipboardDirections,
}
impl Permitted {
    fn for_permit(permit: &VerifiedPermit) -> Self {
        let has =
            |permission: Permission| permit.claims().permissions.contains(&(permission as i32));
        Self {
            file_read: has(Permission::FileRead),
            file_write: has(Permission::FileWrite),
            clipboard: ClipboardDirections {
                read: has(Permission::ClipboardRead),
                write: has(Permission::ClipboardWrite),
            },
        }
    }
}

#[derive(Default)]
struct ClipboardState {
    server: Option<ClipboardServerDeviceControl>,
    approval: Option<LocalClipboardApprovalControl>,
    installed: bool,
}
struct DataSession {
    binding: BrowserHostBinding,
    core: CoreHandle,
    permitted: Permitted,
    lease: LeaseControl,
    active: AtomicBool,
    retained: AtomicBool,
    local_read: AtomicBool,
    local_write: AtomicBool,
    restart_required: AtomicBool,
    clipboard: Mutex<ClipboardState>,
}
impl DataSession {
    fn check(&self, channels: &[Channel]) -> io::Result<()> {
        if !self.active.load(Ordering::Acquire)
            || self.core.browser_host_data_binding().as_ref() != Some(&self.binding)
        {
            return Err(denied());
        }
        // Core publication may lag a stop of the actual business lease.
        self.lease
            .check_channel_binding(Channel::Video, self.binding.connection_generation)
            .map_err(io::Error::other)?;
        for &channel in channels {
            let permitted = match channel {
                Channel::FileRead => self.permitted.file_read,
                Channel::FileWrite => self.permitted.file_write,
                Channel::ClipboardRead => self.permitted.clipboard.read,
                Channel::ClipboardWrite => self.permitted.clipboard.write,
                _ => false,
            };
            if !permitted {
                return Err(denied());
            }
            self.lease
                .check_channel_binding(channel, self.binding.connection_generation)
                .map_err(io::Error::other)?;
            if matches!(channel, Channel::ClipboardRead | Channel::ClipboardWrite) {
                self.lease
                    .check_clipboard_binding(
                        &self.binding.session_id,
                        channel,
                        self.binding.connection_generation,
                    )
                    .map_err(io::Error::other)?;
            }
        }
        Ok(())
    }
    fn platform_allowed(&self, read: bool) -> bool {
        let selected = if read {
            &self.local_read
        } else {
            &self.local_write
        };
        selected.load(Ordering::Acquire)
            && self
                .check(&[if read {
                    Channel::ClipboardRead
                } else {
                    Channel::ClipboardWrite
                }])
                .is_ok()
    }
    fn retire(&self) {
        self.active.store(false, Ordering::Release);
        self.local_read.store(false, Ordering::Release);
        self.local_write.store(false, Ordering::Release);
        self.restart_required.store(true, Ordering::Release);
        let clipboard = lock(&self.clipboard);
        if let Some(approval) = clipboard.approval.as_ref() {
            approval.revoke_all();
        }
        if let Some(server) = clipboard.server.as_ref() {
            server.revoke_all();
        }
    }
    fn observe_revocations(&self) {
        let remove_read = self.local_read.load(Ordering::Acquire) && !self.platform_allowed(true);
        let remove_write =
            self.local_write.load(Ordering::Acquire) && !self.platform_allowed(false);
        if !remove_read && !remove_write {
            return;
        }
        let state = lock(&self.clipboard);
        if let Some(approval) = state.approval.as_ref() {
            if remove_read {
                approval.revoke_read();
            }
            if remove_write {
                approval.revoke_write();
            }
        }
        if let Some(server) = state.server.as_ref() {
            server.revoke(remove_read, remove_write);
        }
        if remove_read {
            self.local_read.store(false, Ordering::Release);
        }
        if remove_write {
            self.local_write.store(false, Ordering::Release);
        }
        self.restart_required.store(true, Ordering::Release);
    }
}

pub(crate) struct AndroidBrowserDataRegistry {
    files: Arc<Mutex<AndroidHostFiles>>,
    session: Mutex<Option<Arc<DataSession>>>,
}
impl AndroidBrowserDataRegistry {
    pub(crate) fn new(files: Arc<Mutex<AndroidHostFiles>>) -> Self {
        Self {
            files,
            session: Mutex::new(None),
        }
    }
    pub(crate) fn supports_files(&self) -> bool {
        true
    }
    pub(crate) fn supports_clipboard(&self) -> bool {
        true
    }

    /// This phase retains metadata only. Claims are unavailable until proof.
    pub(crate) fn prepare_factory(
        self: &Arc<Self>,
        core: CoreHandle,
        request_id: &str,
        permit: &VerifiedPermit,
    ) -> Result<HostDataFactory, BrowserHostError> {
        let binding = browser_host_binding(request_id, permit)?;
        let expected = Permitted::for_permit(permit);
        let registry = self.clone();
        Ok(Box::new(move |claims: HostDataClaims| {
            if claims.file_read.is_some() != expected.file_read
                || claims.file_write.is_some() != expected.file_write
                || claims.clipboard.is_some() == expected.clipboard.is_empty()
            {
                return Err(WebRtcHostError::Permit);
            }
            let proof = claims
                .file_read
                .as_ref()
                .map(|claim| claim.lease_control())
                .or_else(|| {
                    claims
                        .file_write
                        .as_ref()
                        .map(|claim| claim.lease_control())
                })
                .or_else(|| claims.clipboard.as_ref().map(|claim| claim.lease_control()))
                .ok_or(WebRtcHostError::Permit)?;
            if let Some(claim) = claims.file_read.as_ref() {
                if claim.generation() != binding.connection_generation {
                    return Err(WebRtcHostError::Permit);
                }
                claim
                    .lease_control()
                    .check_channel_binding(Channel::FileRead, binding.connection_generation)?;
            }
            if let Some(claim) = claims.file_write.as_ref() {
                if claim.generation() != binding.connection_generation {
                    return Err(WebRtcHostError::Permit);
                }
                claim
                    .lease_control()
                    .check_channel_binding(Channel::FileWrite, binding.connection_generation)?;
            }
            if let Some(claim) = claims.clipboard.as_ref() {
                if claim.binding()
                    != &(WireBinding {
                        session_id: binding.session_id.clone(),
                        connection_generation: binding.connection_generation,
                    })
                    || claim.directions().read != expected.clipboard.read
                    || claim.directions().write != expected.clipboard.write
                {
                    return Err(WebRtcHostError::Permit);
                }
                for channel in [Channel::ClipboardRead, Channel::ClipboardWrite] {
                    if (channel == Channel::ClipboardRead && expected.clipboard.read)
                        || (channel == Channel::ClipboardWrite && expected.clipboard.write)
                    {
                        proof.check_clipboard_binding(
                            &binding.session_id,
                            channel,
                            binding.connection_generation,
                        )?;
                    }
                }
            }
            let mut slot = lock(&registry.session);
            if slot
                .as_ref()
                .is_some_and(|session| session.retained.load(Ordering::Acquire))
            {
                return Err(WebRtcHostError::Permit);
            }
            let (clipboard, clipboard_control) = if let Some(transport) = claims.clipboard {
                let (server, control) =
                    ClipboardServer::start_claimed_switchable(transport, expected.clipboard)?;
                (Some(server), Some(control))
            } else {
                (None, None)
            };
            let session = Arc::new(DataSession {
                binding: binding.clone(),
                core: core.clone(),
                permitted: expected,
                lease: proof.clone(),
                active: AtomicBool::new(true),
                retained: AtomicBool::new(true),
                local_read: AtomicBool::new(false),
                local_write: AtomicBool::new(false),
                restart_required: AtomicBool::new(false),
                clipboard: Mutex::new(ClipboardState {
                    server: clipboard_control.clone(),
                    ..ClipboardState::default()
                }),
            });
            *slot = Some(session.clone());
            drop(slot);
            let mut owner = AndroidBrowserDataOwner {
                session,
                files: None,
                clipboard,
                clipboard_control,
            };
            if expected.file_read || expected.file_write {
                match AndroidBrowserFileOwner::start(
                    registry.files.clone(),
                    core,
                    binding,
                    expected.file_read,
                    expected.file_write,
                    claims.file_read,
                    claims.file_write,
                ) {
                    Ok(files) => owner.files = Some(files),
                    Err(_) => {
                        // A clipboard worker may already exist. Return its stopped
                        // owner so SDK cleanup retains and joins that worker.
                        owner.session.retire();
                        let _ = proof.stop(StopReason::PlatformChanged);
                    }
                }
            }
            Ok(Box::new(owner) as Box<dyn HostDataOwner>)
        }))
    }

    fn get(&self, binding: &BrowserHostBinding) -> Result<Arc<DataSession>, String> {
        lock(&self.session)
            .as_ref()
            .filter(|session| session.binding == *binding)
            .cloned()
            .ok_or_else(|| local_error("missing proof"))
    }
    pub(crate) fn platform_allowed(&self, binding: &BrowserHostBinding, read: bool) -> bool {
        self.get(binding)
            .is_ok_and(|session| session.platform_allowed(read))
    }
    pub(crate) fn files_platform_allowed(&self, binding: &BrowserHostBinding, write: bool) -> bool {
        self.get(binding).is_ok_and(|session| {
            session
                .check(&[if write {
                    Channel::FileWrite
                } else {
                    Channel::FileRead
                }])
                .is_ok()
        })
    }
    pub(crate) fn retire(&self) {
        let session = lock(&self.session).clone();
        if let Some(session) = session {
            session.retire();
        }
    }
    pub(crate) fn view(
        &self,
        core: &CoreHandle,
        binding: &BrowserHostBinding,
    ) -> Result<BrowserHostDataView, String> {
        if core.browser_host_data_binding().as_ref() != Some(binding) {
            return Err(local_error("replaced host"));
        }
        let snapshot = core.snapshot();
        let mut data = snapshot
            .browser_host
            .data
            .as_ref()
            .filter(|host| host.binding.as_ref() == Some(binding))
            .map(|host| host.data.clone())
            .ok_or_else(|| local_error("replaced host"))?;
        // The SDK never claims optional data channels for a view/input/audio
        // only permit. Such a connected proof has no retained data owner.
        if let Some(empty) = view_without_data_owner(&data) {
            if core.browser_host_data_binding().as_ref() != Some(binding) {
                return Err(local_error("replaced host"));
            }
            return Ok(empty);
        }
        let session = self.get(binding)?;
        session.check(&[]).map_err(local_error)?;
        session.observe_revocations();
        let (reads, writes) = lock(&self.files).browser_roots(core, binding)?;
        data.read_roots = reads;
        data.write_roots = writes;
        data.local_file_read = !data.read_roots.is_empty();
        data.local_file_write = !data.write_roots.is_empty();
        data.local_clipboard_read = session.local_read.load(Ordering::Acquire);
        data.local_clipboard_write = session.local_write.load(Ordering::Acquire);
        data.clipboard_restart_required = session.restart_required.load(Ordering::Acquire);
        session.check(&[]).map_err(local_error)?;
        Ok(data)
    }

    /// JNI invokes this only for an explicit local direction choice. The
    /// reentrant platform authorization path below reads atomics, not this lock.
    pub(crate) fn set_directions(
        &self,
        binding: &BrowserHostBinding,
        read: bool,
        write: bool,
        factory: Option<AndroidBrowserClipboardFactory>,
    ) -> Result<(), String> {
        let session = self.get(binding)?;
        let channels = selected_channels(read, write);
        session.check(&channels).map_err(local_error)?;
        let mut state = lock(&session.clipboard);
        let old_read = session.local_read.load(Ordering::Acquire);
        let old_write = session.local_write.load(Ordering::Acquire);
        if state.installed {
            if factory.is_some() || (read && !old_read) || (write && !old_write) {
                return Err("Adding a clipboard direction requires a new browser session".into());
            }
            let removed_read = old_read && !read;
            let removed_write = old_write && !write;
            if let Some(approval) = state.approval.as_ref() {
                if removed_read {
                    approval.revoke_read();
                }
                if removed_write {
                    approval.revoke_write();
                }
            }
            if let Some(server) = state.server.as_ref() {
                server.revoke(removed_read, removed_write);
            }
            session.local_read.store(read, Ordering::Release);
            session.local_write.store(write, Ordering::Release);
            if removed_read || removed_write {
                session.restart_required.store(true, Ordering::Release);
            }
        } else if read || write {
            if session.restart_required.load(Ordering::Acquire) {
                return Err("Clipboard approval requires a new browser session".into());
            }
            let factory =
                factory.ok_or_else(|| "Local Android clipboard endpoint is required".to_owned())?;
            let server = state
                .server
                .clone()
                .ok_or_else(|| local_error("missing clipboard owner"))?;
            let platform_binding = PlatformBinding {
                session_id: binding.session_id.clone(),
                connection_generation: binding.connection_generation,
            };
            let (approval, control) = LocalClipboardApproval::approve_from_local_user(
                platform_binding.clone(),
                read,
                write,
            )
            .map_err(local_error)?;
            let authority: Arc<dyn ClipboardAuthority> = Arc::new(BrowserClipboardAuthority {
                session: session.clone(),
            });
            // The platform worker checks authority during open, before any OS
            // read/write. This explicit choice is revoked if installation fails.
            session.local_read.store(read, Ordering::Release);
            session.local_write.store(write, Ordering::Release);
            let platform = match factory.open(platform_binding, approval, authority) {
                Ok(platform) => platform,
                Err(error) => {
                    control.revoke_all();
                    session.local_read.store(false, Ordering::Release);
                    session.local_write.store(false, Ordering::Release);
                    session.restart_required.store(true, Ordering::Release);
                    return Err(local_error(error));
                }
            };
            let device = BrowserClipboardDevice {
                binding: WireBinding {
                    session_id: binding.session_id.clone(),
                    connection_generation: binding.connection_generation,
                },
                platform,
            };
            // install retains a rejected device until platform cleanup completes.
            if let Err(error) = server.install(device, ClipboardDirections { read, write }) {
                control.revoke_all();
                session.local_read.store(false, Ordering::Release);
                session.local_write.store(false, Ordering::Release);
                session.restart_required.store(true, Ordering::Release);
                return Err(local_error(error));
            }
            state.approval = Some(control);
            state.installed = true;
            session.local_read.store(read, Ordering::Release);
            session.local_write.store(write, Ordering::Release);
        } else if factory.is_some() {
            return Err("No local clipboard direction was selected".into());
        }
        drop(state);
        if let Err(error) = session.check(&channels) {
            session.retire();
            return Err(local_error(error));
        }
        Ok(())
    }
}

fn view_without_data_owner(data: &BrowserHostDataView) -> Option<BrowserHostDataView> {
    if data.permitted_file_read
        || data.permitted_file_write
        || data.permitted_clipboard_read
        || data.permitted_clipboard_write
    {
        return None;
    }
    Some(BrowserHostDataView {
        files_available: data.files_available,
        clipboard_available: data.clipboard_available,
        ..BrowserHostDataView::default()
    })
}

fn selected_channels(read: bool, write: bool) -> Vec<Channel> {
    let mut channels = Vec::with_capacity(2);
    if read {
        channels.push(Channel::ClipboardRead);
    }
    if write {
        channels.push(Channel::ClipboardWrite);
    }
    channels
}

struct AndroidBrowserDataOwner {
    session: Arc<DataSession>,
    files: Option<AndroidBrowserFileOwner>,
    clipboard: Option<ClipboardServer>,
    clipboard_control: Option<ClipboardServerDeviceControl>,
}
impl HostDataOwner for AndroidBrowserDataOwner {
    fn shutdown<'a>(
        &'a mut self,
        reason: StopReason,
    ) -> Pin<Box<dyn Future<Output = Result<(), RemoteError>> + Send + 'a>> {
        Box::pin(async move {
            self.session.retire();
            let mut failure = None;
            if let Some(files) = self.files.as_mut() {
                match files.shutdown(reason).await {
                    Ok(()) => self.files = None,
                    Err(error) => failure = Some(error),
                }
            }
            if let Some(control) = self.clipboard_control.as_ref()
                && let Err(error) = control.close_device()
            {
                failure.get_or_insert(RemoteError::Cleanup(error));
            }
            if let Some(server) = self.clipboard.as_mut() {
                match server.shutdown(reason).await {
                    Ok(ClipboardShutdown::Finished) => {
                        self.clipboard = None;
                        self.clipboard_control = None;
                    }
                    Ok(ClipboardShutdown::Pending) => {
                        failure.get_or_insert(RemoteError::Cleanup(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Android browser clipboard cleanup remains pending",
                        )));
                    }
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                }
            }
            if let Some(error) = failure {
                return Err(error);
            }
            self.session.retained.store(false, Ordering::Release);
            Ok(())
        })
    }
}

struct BrowserClipboardAuthority {
    session: Arc<DataSession>,
}
impl ClipboardAuthority for BrowserClipboardAuthority {
    fn check(&self, binding: &PlatformBinding, direction: PlatformDirection) -> io::Result<()> {
        if binding.session_id != self.session.binding.session_id
            || binding.connection_generation != self.session.binding.connection_generation
            || !self
                .session
                .platform_allowed(direction == PlatformDirection::Read)
        {
            return Err(denied());
        }
        Ok(())
    }
}
struct PlatformConsent(nestlink_platform_clipboard::ClipboardDirectionGuard);
impl ClipboardConsent for PlatformConsent {
    fn check_until(&self, deadline: Instant) -> io::Result<()> {
        self.0.check_until(deadline)
    }
}
struct BrowserClipboardDevice {
    binding: WireBinding,
    platform: Box<dyn NativeClipboard>,
}
impl ClipboardDevice for BrowserClipboardDevice {
    fn binding(&self) -> &WireBinding {
        &self.binding
    }
    fn consent(&self, direction: ClipboardDirection) -> Arc<dyn ClipboardConsent> {
        Arc::new(PlatformConsent(self.platform.direction_guard(
            match direction {
                ClipboardDirection::Read => PlatformDirection::Read,
                ClipboardDirection::Write => PlatformDirection::Write,
            },
        )))
    }
    fn read_text(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Option<String>> {
        authorized()?;
        let text = self.platform.read_text()?.map(zeroize::Zeroizing::new);
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
        match self.platform.write_text(text) {
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
        self.platform.close()
    }
    fn cleanup_complete(&self) -> bool {
        matches!(
            self.platform.monitor().status().cleanup,
            nestlink_platform_clipboard::ClipboardCleanup::Complete
        )
    }
}

#[cfg(test)]
mod tests {
    use super::view_without_data_owner;
    use nestlink_app_core::{BrowserHostDataView, BrowserHostFileRootView};

    #[test]
    fn view_only_proof_needs_no_optional_owner_and_cannot_retain_local_approval() {
        let stale = BrowserHostDataView {
            files_available: true,
            clipboard_available: true,
            local_file_read: true,
            local_file_write: true,
            local_clipboard_read: true,
            local_clipboard_write: true,
            clipboard_restart_required: true,
            read_roots: vec![BrowserHostFileRootView {
                root_id: "stale-read".into(),
                display_name: "Old selection".into(),
            }],
            write_roots: vec![BrowserHostFileRootView {
                root_id: "stale-write".into(),
                display_name: "Old selection".into(),
            }],
            ..BrowserHostDataView::default()
        };
        assert_eq!(
            view_without_data_owner(&stale),
            Some(BrowserHostDataView {
                files_available: true,
                clipboard_available: true,
                ..BrowserHostDataView::default()
            })
        );
        for direction in 0..4 {
            let mut permitted = stale.clone();
            match direction {
                0 => permitted.permitted_file_read = true,
                1 => permitted.permitted_file_write = true,
                2 => permitted.permitted_clipboard_read = true,
                _ => permitted.permitted_clipboard_write = true,
            }
            assert!(view_without_data_owner(&permitted).is_none());
        }
    }
}
