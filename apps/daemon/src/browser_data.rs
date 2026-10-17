//! Browser-host local data grants. Every browser proof gets its own empty
//! roots and clipboard owner; native session approvals are never reused.
use crate::native_files::{RootBudget, RootPermit};
use nestlink_app_core::{
    BrowserHostBinding, BrowserHostDataError, BrowserHostDataView, BrowserHostError,
    BrowserHostFileRootView, CoreHandle,
};
use nestlink_app_ipc::{
    browser_data::{
        BrowserHostDataCommand, BrowserHostDataReply, BrowserHostDataReplyFuture,
        LocalBrowserHostDataHandler,
    },
    files::{FileDirection, LocalReadRootSelection, LocalWriteRootSelection},
};
use nestlink_identity::VerifiedPermit;
use nestlink_platform_clipboard::{
    ClipboardAuthority, ClipboardBinding as PlatformClipboardBinding,
    ClipboardDirection as PlatformClipboardDirection, LocalClipboardApproval,
    LocalClipboardApprovalControl, NativeClipboard as PlatformClipboard,
};
use nestlink_platform_files::{
    ApprovedReadRoot, FileRoots, ReadRootConsent,
    browse::{BrowseConsent, BrowseLimits, BrowseSelection, network::BrowseRoots},
    upload::{WriteQuota, WriteRootConsent, WriteRootSelection, WriteRoots},
};
use nestlink_protocol::{
    DirectoryBrowsePage, FILE_READ_ROOTS, FILE_SIZE_BYTES, FILE_WRITE_ROOTS, FileReadManifest,
    FileWriteChunk, FileWriteOpen, FileWriteState, Permission,
};
use nestlink_remote::{
    LeaseControl, RemoteError,
    clipboard::{
        ClipboardBinding as WireClipboardBinding, ClipboardConsent,
        ClipboardDevice as RemoteClipboardDevice, ClipboardDirection as RemoteClipboardDirection,
        ClipboardDirections, ClipboardServer, ClipboardServerDeviceControl, ClipboardWriteOutcome,
    },
    files::{
        DirectoryBrowseSource, FileReadConsent, FileReadDevice, FileReadRootListing,
        FileReadServer, FileReadSource, FileShutdown,
    },
    upload::{FileWriteConsent, FileWriteDevice, FileWriteRootListing, FileWriteServer},
};
use nestlink_sdk::webrtc_host::{HostDataClaims, HostDataFactory, HostDataOwner, WebRtcHostError};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    io,
    path::PathBuf,
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
        "browser-host data approval is inactive",
    )
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid local browser-host selection",
    )
}
fn absolute(value: &str) -> io::Result<PathBuf> {
    let path = PathBuf::from(value);
    if value.is_empty() || value.contains('\0') || !path.is_absolute() {
        Err(invalid())
    } else {
        Ok(path)
    }
}
fn label(value: &str) -> io::Result<()> {
    if value.is_empty()
        || value.trim() != value
        || value.len() as u64 > nestlink_protocol::FILE_ROOT_DISPLAY_NAME_BYTES
        || value
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '/' | '\\' | ':'))
    {
        Err(invalid())
    } else {
        Ok(())
    }
}

fn required_channels(command: &BrowserHostDataCommand) -> Vec<Channel> {
    match command {
        BrowserHostDataCommand::SelectReadRoots { .. } => vec![Channel::FileRead],
        BrowserHostDataCommand::SelectWriteRoots { .. } => vec![Channel::FileWrite],
        // Local revocation only removes a capability, so it remains available
        // after the lease loses the direction being revoked.
        BrowserHostDataCommand::RevokeRoot { .. } => Vec::new(),
        BrowserHostDataCommand::SetClipboardDirections { read, write } => {
            let mut channels = Vec::with_capacity(2);
            if *read {
                channels.push(Channel::ClipboardRead);
            }
            if *write {
                channels.push(Channel::ClipboardWrite);
            }
            channels
        }
    }
}

#[derive(Clone, Copy)]
struct Permitted {
    file_read: bool,
    file_write: bool,
    clipboard_read: bool,
    clipboard_write: bool,
}
struct ClipboardState {
    server: Option<ClipboardServerDeviceControl>,
    lease: Option<LeaseControl>,
    approval: Option<LocalClipboardApprovalControl>,
    read: bool,
    write: bool,
    restart_required: bool,
}
struct BrowserDataSession {
    binding: BrowserHostBinding,
    permitted: Permitted,
    active: Arc<AtomicBool>,
    reads: ReadRegistry,
    writes: WriteRegistry,
    lease: Mutex<Option<LeaseControl>>,
    clipboard: Mutex<ClipboardState>,
}
impl BrowserDataSession {
    fn check_live(&self, channels: &[Channel]) -> io::Result<()> {
        if !self.active.load(Ordering::Acquire) {
            return Err(denied());
        }
        let lease = lock(&self.lease).clone().ok_or_else(denied)?;
        let generation = self.binding.connection_generation;
        for &channel in channels {
            let permitted = match channel {
                Channel::FileRead => self.permitted.file_read,
                Channel::FileWrite => self.permitted.file_write,
                Channel::ClipboardRead => self.permitted.clipboard_read,
                Channel::ClipboardWrite => self.permitted.clipboard_write,
                _ => false,
            };
            if !permitted {
                return Err(denied());
            }
            lease
                .check_channel_binding(channel, generation)
                .map_err(io::Error::other)?;
            if matches!(channel, Channel::ClipboardRead | Channel::ClipboardWrite) {
                lease
                    .check_clipboard_binding(&self.binding.session_id, channel, generation)
                    .map_err(io::Error::other)?;
            }
        }
        Ok(())
    }
    fn retire(&self) {
        self.active.store(false, Ordering::Release);
        for entry in lock(&self.reads).values() {
            entry.active.store(false, Ordering::Release);
        }
        for entry in lock(&self.writes).values() {
            entry.active.store(false, Ordering::Release);
        }
        let mut clipboard = lock(&self.clipboard);
        if let Some(approval) = clipboard.approval.as_ref() {
            approval.revoke_all();
        }
        if let Some(server) = clipboard.server.as_ref() {
            server.revoke_all();
        }
        clipboard.read = false;
        clipboard.write = false;
        clipboard.restart_required = true;
    }
    fn roots(&self, direction: FileDirection) -> Vec<BrowserHostFileRootView> {
        let entries: Vec<_> = match direction {
            FileDirection::Read => lock(&self.reads)
                .values()
                .filter(|entry| entry.approval.check().is_ok())
                .map(|entry| (entry.id.clone(), entry.name.clone()))
                .collect(),
            FileDirection::Write => lock(&self.writes)
                .values()
                .filter(|entry| entry.approval.check().is_ok())
                .map(|entry| (entry.id.clone(), entry.name.clone()))
                .collect(),
        };
        entries
            .into_iter()
            .map(|(root_id, display_name)| BrowserHostFileRootView {
                root_id,
                display_name,
            })
            .collect()
    }
    fn view(&self, mut data: BrowserHostDataView) -> BrowserHostDataView {
        data.read_roots = self.roots(FileDirection::Read);
        data.write_roots = self.roots(FileDirection::Write);
        data.local_file_read = !data.read_roots.is_empty();
        data.local_file_write = !data.write_roots.is_empty();
        let clipboard = lock(&self.clipboard);
        data.local_clipboard_read = clipboard.read;
        data.local_clipboard_write = clipboard.write;
        data.clipboard_restart_required = clipboard.restart_required;
        data
    }
}

#[derive(Default)]
pub struct BrowserHostDataRegistry {
    sessions: Mutex<HashMap<BrowserHostBinding, Arc<BrowserDataSession>>>,
}
impl BrowserHostDataRegistry {
    fn prepare(
        &self,
        binding: BrowserHostBinding,
        permit: &VerifiedPermit,
    ) -> Result<Arc<BrowserDataSession>, BrowserHostError> {
        let claims = permit.claims();
        if claims.session_id != binding.session_id
            || claims.controller_device_id != binding.controller_device_id
            || claims.host_device_id != binding.host_device_id
            || claims.controller_key_sha256.as_slice() != binding.controller_key_sha256
            || claims.host_key_sha256.as_slice() != binding.host_key_sha256
            || claims.connection_generation != binding.connection_generation
            || permit.digest() != binding.permit_sha256
        {
            return Err(BrowserHostError::SessionBinding);
        }
        let has = |permission: Permission| claims.permissions.contains(&(permission as i32));
        let session = Arc::new(BrowserDataSession {
            binding: binding.clone(),
            permitted: Permitted {
                file_read: has(Permission::FileRead),
                file_write: has(Permission::FileWrite),
                clipboard_read: has(Permission::ClipboardRead),
                clipboard_write: has(Permission::ClipboardWrite),
            },
            active: Arc::new(AtomicBool::new(true)),
            reads: Arc::new(Mutex::new(BTreeMap::new())),
            writes: Arc::new(Mutex::new(BTreeMap::new())),
            lease: Mutex::new(None),
            clipboard: Mutex::new(ClipboardState {
                server: None,
                lease: None,
                approval: None,
                read: false,
                write: false,
                restart_required: false,
            }),
        });
        let mut sessions = lock(&self.sessions);
        if let Some(previous) = sessions.insert(binding, session.clone()) {
            previous.retire();
        }
        Ok(session)
    }
    fn get(&self, binding: &BrowserHostBinding) -> Option<Arc<BrowserDataSession>> {
        lock(&self.sessions).get(binding).cloned()
    }
    fn retire_except(&self, current: Option<&BrowserHostBinding>, pending: Option<(&str, u64)>) {
        lock(&self.sessions).retain(|binding, session| {
            if (current == Some(binding)
                || pending.is_some_and(|(request_id, connection_generation)| {
                    binding.request_id == request_id
                        && binding.connection_generation == connection_generation
                }))
                && session.active.load(Ordering::Acquire)
            {
                true
            } else {
                session.retire();
                false
            }
        });
    }
}

pub struct LocalBrowserHostData {
    core: CoreHandle,
    registry: Arc<BrowserHostDataRegistry>,
    root_budget: Arc<RootBudget>,
    write_quota: Arc<WriteQuota>,
}
impl LocalBrowserHostData {
    pub fn new(
        core: CoreHandle,
        registry: Arc<BrowserHostDataRegistry>,
        root_budget: Arc<RootBudget>,
        write_quota: Arc<WriteQuota>,
    ) -> Self {
        let mut observed = core.observe();
        let cleanup = registry.clone();
        tokio::spawn(async move {
            loop {
                let snapshot = observed.borrow_and_update().clone();
                let current = snapshot.browser_host.data.as_ref().and_then(|host| {
                    if host.status == nestlink_app_core::BrowserHostStatus::Connected
                        && host.host_view_authorized
                    {
                        host.binding.as_ref()
                    } else {
                        None
                    }
                });
                let pending = snapshot.browser_host.data.as_ref().and_then(|host| {
                    (host.status == nestlink_app_core::BrowserHostStatus::Establishing)
                        .then_some((host.request_id.as_str(), host.connection_generation))
                });
                cleanup.retire_except(current, pending);
                if observed.changed().await.is_err() {
                    return;
                }
            }
        });
        Self {
            core,
            registry,
            root_budget,
            write_quota,
        }
    }
    async fn execute(
        &self,
        binding: &BrowserHostBinding,
        generation: u64,
        command: BrowserHostDataCommand,
    ) -> Result<BrowserHostDataView, String> {
        let channels = required_channels(&command);
        if self.core.snapshot().generation != generation {
            return Err(BrowserHostDataError::StaleGeneration.to_string());
        }
        if self.core.browser_host_data_binding().as_ref() != Some(binding) {
            return Err(BrowserHostDataError::StaleBinding.to_string());
        }
        let session = self
            .registry
            .get(binding)
            .filter(|session| session.binding == *binding)
            .ok_or_else(|| BrowserHostDataError::StaleBinding.to_string())?;
        session.check_live(&channels).map_err(local_error)?;
        let data = self
            .core
            .snapshot()
            .browser_host
            .data
            .as_ref()
            .filter(|host| host.binding.as_ref() == Some(binding))
            .map(|host| host.data.clone())
            .ok_or_else(|| BrowserHostDataError::StaleBinding.to_string())?;
        match command {
            BrowserHostDataCommand::SelectReadRoots { roots } => {
                if !data.files_available || !session.permitted.file_read {
                    return Err(
                        "File reading is unavailable or not permitted for this browser session"
                            .into(),
                    );
                }
                if roots.is_empty() || roots.len() as u64 > FILE_READ_ROOTS {
                    return Err("Shared-folder selection capacity exceeded".into());
                }
                lock(&session.reads).retain(|_, entry| entry.approval.check().is_ok());
                let pending = build_read_roots(&session, roots, self.root_budget.clone())
                    .map_err(local_error)?;
                let mut registry = lock(&session.reads);
                registry.retain(|_, entry| entry.approval.check().is_ok());
                if registry.len() + pending.len() > FILE_READ_ROOTS as usize {
                    return Err("Shared-folder selection capacity exceeded".into());
                }
                for entry in pending {
                    registry.insert(entry.id.clone(), entry);
                }
            }
            BrowserHostDataCommand::SelectWriteRoots { roots } => {
                if !data.files_available || !session.permitted.file_write {
                    return Err(
                        "File writing is unavailable or not permitted for this browser session"
                            .into(),
                    );
                }
                if roots.is_empty() || roots.len() as u64 > FILE_WRITE_ROOTS {
                    return Err("Receiving-folder selection capacity exceeded".into());
                }
                lock(&session.writes).retain(|_, entry| entry.approval.check().is_ok());
                let pending = build_write_roots(
                    &session,
                    roots,
                    self.root_budget.clone(),
                    self.write_quota.clone(),
                )
                .map_err(local_error)?;
                let mut registry = lock(&session.writes);
                registry.retain(|_, entry| entry.approval.check().is_ok());
                if registry.len() + pending.len() > FILE_WRITE_ROOTS as usize {
                    return Err("Receiving-folder selection capacity exceeded".into());
                }
                for entry in pending {
                    registry.insert(entry.id.clone(), entry);
                }
            }
            BrowserHostDataCommand::RevokeRoot { direction, root_id } => {
                if !nestlink_protocol::valid_id(&root_id) {
                    return Err("The selected folder is unavailable".into());
                }
                let active = match direction {
                    FileDirection::Read => lock(&session.reads)
                        .remove(&root_id)
                        .map(|entry| entry.active.clone()),
                    FileDirection::Write => lock(&session.writes)
                        .remove(&root_id)
                        .map(|entry| entry.active.clone()),
                }
                .ok_or_else(|| "The selected folder is unavailable".to_owned())?;
                active.store(false, Ordering::Release);
            }
            BrowserHostDataCommand::SetClipboardDirections { read, write } => {
                if !data.clipboard_available
                    || (read && !session.permitted.clipboard_read)
                    || (write && !session.permitted.clipboard_write)
                {
                    return Err("Clipboard direction is unavailable or not permitted for this browser session".into());
                }
                let mut clipboard = lock(&session.clipboard);
                if clipboard.restart_required
                    && ((read && !clipboard.read) || (write && !clipboard.write))
                {
                    return Err(
                        "Adding a clipboard direction requires a new browser session".into(),
                    );
                }
                if !clipboard.read && !clipboard.write && (read || write) {
                    let lease = clipboard
                        .lease
                        .clone()
                        .ok_or_else(|| "Clipboard owner is unavailable".to_owned())?;
                    let (device, approval) =
                        open_clipboard(binding, lease, read, write).map_err(local_error)?;
                    let server = clipboard
                        .server
                        .as_ref()
                        .ok_or_else(|| "Clipboard owner is unavailable".to_owned())?;
                    server
                        .install(device, ClipboardDirections { read, write })
                        .map_err(|_| {
                            "Local clipboard approval could not be installed".to_owned()
                        })?;
                    clipboard.approval = Some(approval);
                } else {
                    let removed_read = clipboard.read && !read;
                    let removed_write = clipboard.write && !write;
                    if removed_read || removed_write {
                        if let Some(approval) = clipboard.approval.as_ref() {
                            if removed_read {
                                approval.revoke_read();
                            }
                            if removed_write {
                                approval.revoke_write();
                            }
                        }
                        if let Some(server) = clipboard.server.as_ref() {
                            server.revoke(removed_read, removed_write);
                        }
                        clipboard.restart_required = true;
                    }
                }
                clipboard.read = read;
                clipboard.write = write;
            }
        }
        session.check_live(&channels).map_err(local_error)?;
        let updated = session.view(data);
        self.core
            .update_browser_host_data(binding.clone(), generation, updated.clone())
            .await
            .map_err(|error| error.to_string())?;
        Ok(updated)
    }
}
impl LocalBrowserHostDataHandler for LocalBrowserHostData {
    fn handle(
        &self,
        _core: CoreHandle,
        binding: BrowserHostBinding,
        generation: u64,
        command: BrowserHostDataCommand,
    ) -> BrowserHostDataReplyFuture<'_> {
        Box::pin(async move {
            match self.execute(&binding, generation, command).await {
                Ok(data) => BrowserHostDataReply::Applied { data },
                Err(reason) => BrowserHostDataReply::Refused { reason },
            }
        })
    }
}

fn build_read_roots(
    session: &BrowserDataSession,
    roots: Vec<LocalReadRootSelection>,
    root_budget: Arc<RootBudget>,
) -> io::Result<Vec<Arc<ReadEntry>>> {
    let mut pending = Vec::with_capacity(roots.len());
    for root in roots {
        let slot = root_budget.reserve(FileDirection::Read)?;
        label(&root.display_name)?;
        let path = absolute(&root.directory)?;
        let id = nestlink_auth::random_id();
        let (browse, browse_consent) = if root.disclose_directory {
            let (selection, consent) = BrowseSelection::new_with_display_name(
                &id,
                &root.display_name,
                &path,
                BrowseLimits::default(),
            )?;
            (Some(selection), Some(consent))
        } else {
            (None, None)
        };
        let active = Arc::new(AtomicBool::new(true));
        pending.push(Arc::new(ReadEntry {
            id,
            name: root.display_name,
            active: active.clone(),
            approval: Arc::new(Approval(vec![session.active.clone(), active])),
            provider: Mutex::new(ReadProvider {
                path: Some(path),
                browse,
                device: None,
                _read_consent: None,
                _browse_consent: browse_consent,
            }),
            _slot: Some(slot),
        }));
    }
    Ok(pending)
}
fn build_write_roots(
    session: &BrowserDataSession,
    roots: Vec<LocalWriteRootSelection>,
    root_budget: Arc<RootBudget>,
    write_quota: Arc<WriteQuota>,
) -> io::Result<Vec<Arc<WriteEntry>>> {
    let mut pending = Vec::with_capacity(roots.len());
    for root in roots {
        let slot = root_budget.reserve(FileDirection::Write)?;
        label(&root.display_name)?;
        let path = absolute(&root.fresh_directory)?;
        let id = nestlink_auth::random_id();
        let (selection, consent) = WriteRootSelection::new_with_display_name_and_quota(
            &id,
            &root.display_name,
            &path,
            FILE_SIZE_BYTES,
            write_quota.clone(),
        )?;
        let active = Arc::new(AtomicBool::new(true));
        pending.push(Arc::new(WriteEntry {
            id,
            name: root.display_name,
            active: active.clone(),
            approval: Arc::new(Approval(vec![session.active.clone(), active])),
            provider: Mutex::new(WriteRoots::new(vec![selection])?),
            _consent: consent,
            _slot: Some(slot),
        }));
    }
    Ok(pending)
}
fn local_error(error: io::Error) -> String {
    format!(
        "Local browser-host data operation failed: {:?}",
        error.kind()
    )
}

struct Approval(Vec<Arc<AtomicBool>>);
impl Approval {
    fn check(&self) -> io::Result<()> {
        if self.0.iter().all(|flag| flag.load(Ordering::Acquire)) {
            Ok(())
        } else {
            Err(denied())
        }
    }
}
impl FileReadConsent for Approval {
    fn check(&self) -> io::Result<()> {
        self.check()
    }
}
impl FileWriteConsent for Approval {
    fn check(&self) -> io::Result<()> {
        self.check()
    }
}
struct ReadApproval(Arc<dyn FileReadConsent>, Arc<Approval>);
impl FileReadConsent for ReadApproval {
    fn check(&self) -> io::Result<()> {
        self.1.check()?;
        self.0.check()
    }
}
struct WriteApproval(Arc<dyn FileWriteConsent>, Arc<Approval>);
impl FileWriteConsent for WriteApproval {
    fn check(&self) -> io::Result<()> {
        self.1.check()?;
        self.0.check()
    }
}
struct ReadProvider {
    path: Option<PathBuf>,
    browse: Option<BrowseSelection>,
    device: Option<BrowseRoots<FileRoots>>,
    _read_consent: Option<ReadRootConsent>,
    _browse_consent: Option<BrowseConsent>,
}
impl ReadProvider {
    fn device(&mut self, id: &str, approval: &Approval) -> io::Result<&mut BrowseRoots<FileRoots>> {
        approval.check()?;
        if self.device.is_none() {
            let path = self.path.take().ok_or_else(denied)?;
            let (root, consent) = ApprovedReadRoot::open(id, &path, FILE_SIZE_BYTES)?;
            approval.check()?;
            self._read_consent = Some(consent);
            self.device = Some(BrowseRoots::new(
                FileRoots::new(vec![root])?,
                self.browse.take().into_iter().collect(),
            )?);
        }
        self.device.as_mut().ok_or_else(denied)
    }
}
struct ReadEntry {
    id: String,
    name: String,
    active: Arc<AtomicBool>,
    approval: Arc<Approval>,
    provider: Mutex<ReadProvider>,
    // Keep the root counted until its provider has closed.
    _slot: Option<RootPermit>,
}
struct WriteEntry {
    id: String,
    name: String,
    active: Arc<AtomicBool>,
    approval: Arc<Approval>,
    provider: Mutex<WriteRoots>,
    _consent: WriteRootConsent,
    // Declared last so the pinned provider closes before its slot.
    _slot: Option<RootPermit>,
}
type ReadRegistry = Arc<Mutex<BTreeMap<String, Arc<ReadEntry>>>>;
type WriteRegistry = Arc<Mutex<BTreeMap<String, Arc<WriteEntry>>>>;

struct DynamicRead {
    registry: ReadRegistry,
    active: Arc<AtomicBool>,
}
impl FileReadDevice for DynamicRead {
    fn retire_revoked(&mut self) {
        lock(&self.registry).retain(|_, entry| entry.approval.check().is_ok());
    }
    fn list_roots(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadRootListing> {
        authorized()?;
        self.retire_revoked();
        let entries: Vec<_> = lock(&self.registry).values().cloned().collect();
        let mut flags = vec![self.active.clone()];
        let roots = entries
            .iter()
            .map(|entry| {
                flags.push(entry.active.clone());
                nestlink_protocol::FileRoot {
                    root_id: entry.id.clone(),
                    display_name: entry.name.clone(),
                }
            })
            .collect();
        let consent = Arc::new(Approval(flags));
        consent.check()?;
        authorized()?;
        Ok(FileReadRootListing { roots, consent })
    }
    fn open(&mut self, id: &str, path: &str) -> io::Result<Box<dyn FileReadSource>> {
        self.retire_revoked();
        let entry = lock(&self.registry).get(id).cloned().ok_or_else(denied)?;
        entry.approval.check()?;
        let source = lock(&entry.provider)
            .device(id, &entry.approval)?
            .open(id, path)?;
        entry.approval.check()?;
        Ok(Box::new(OwnedSource {
            source,
            approval: entry.approval.clone(),
            _entry: entry,
        }))
    }
    fn browse(
        &mut self,
        id: &str,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn DirectoryBrowseSource>> {
        self.retire_revoked();
        let entry = lock(&self.registry).get(id).cloned().ok_or_else(denied)?;
        entry.approval.check()?;
        authorized()?;
        let source = lock(&entry.provider)
            .device(id, &entry.approval)?
            .browse(id, &mut || {
                entry.approval.check()?;
                authorized()
            })?;
        entry.approval.check()?;
        Ok(Box::new(OwnedBrowse {
            source,
            approval: entry.approval.clone(),
            _entry: entry,
        }))
    }
}

struct DynamicWrite {
    registry: WriteRegistry,
    active: Arc<AtomicBool>,
}
impl FileWriteDevice for DynamicWrite {
    fn retire_revoked(&mut self) {
        lock(&self.registry).retain(|_, entry| entry.approval.check().is_ok());
    }
    fn list_roots(&mut self) -> io::Result<FileWriteRootListing> {
        self.retire_revoked();
        let entries: Vec<_> = lock(&self.registry).values().cloned().collect();
        let mut flags = vec![self.active.clone()];
        let roots = entries
            .iter()
            .map(|entry| {
                flags.push(entry.active.clone());
                nestlink_protocol::FileRoot {
                    root_id: entry.id.clone(),
                    display_name: entry.name.clone(),
                }
            })
            .collect();
        let consent = Arc::new(Approval(flags));
        consent.check()?;
        Ok(FileWriteRootListing { roots, consent })
    }
    fn build(
        &mut self,
        open: &FileWriteOpen,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn nestlink_remote::upload::FileWriteDestination>> {
        self.retire_revoked();
        let entry = lock(&self.registry)
            .get(&open.root_id)
            .cloned()
            .ok_or_else(denied)?;
        entry.approval.check()?;
        let destination = lock(&entry.provider).build(open, &mut || {
            entry.approval.check()?;
            authorized()
        })?;
        entry.approval.check()?;
        Ok(Box::new(OwnedWrite {
            destination,
            approval: entry.approval.clone(),
            _entry: entry,
        }))
    }
}

struct OwnedSource {
    source: Box<dyn FileReadSource>,
    approval: Arc<Approval>,
    _entry: Arc<ReadEntry>,
}
impl FileReadSource for OwnedSource {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(ReadApproval(self.source.consent(), self.approval.clone()))
    }
    fn describe(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest> {
        self.source.describe(&mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn read_chunk(
        &mut self,
        offset: u64,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        self.source.read_chunk(offset, maximum, &mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn verify(
        &mut self,
        original: &FileReadManifest,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.source.verify(original, &mut || {
            self.approval.check()?;
            authorized()
        })
    }
}
struct OwnedBrowse {
    source: Box<dyn DirectoryBrowseSource>,
    approval: Arc<Approval>,
    _entry: Arc<ReadEntry>,
}
impl DirectoryBrowseSource for OwnedBrowse {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        Arc::new(ReadApproval(self.source.consent(), self.approval.clone()))
    }
    fn begin(
        &mut self,
        directory: Option<&str>,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<DirectoryBrowsePage> {
        self.source.begin(directory, maximum, &mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn next(
        &mut self,
        cursor: &[u8],
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<DirectoryBrowsePage> {
        self.source.next(cursor, maximum, &mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn snapshot_deadline(&self) -> io::Result<Instant> {
        self.source.snapshot_deadline()
    }
    fn reply_deadline(&self) -> io::Result<Instant> {
        self.source.reply_deadline()
    }
}
struct OwnedWrite {
    destination: Box<dyn nestlink_remote::upload::FileWriteDestination>,
    approval: Arc<Approval>,
    _entry: Arc<WriteEntry>,
}
impl nestlink_remote::upload::FileWriteDestination for OwnedWrite {
    fn consent(&self) -> Arc<dyn FileWriteConsent> {
        Arc::new(WriteApproval(
            self.destination.consent(),
            self.approval.clone(),
        ))
    }
    fn status(&self) -> FileWriteState {
        self.destination.status()
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.destination.prepare(&mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn write(
        &mut self,
        chunk: &FileWriteChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.destination.write(chunk, &mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn finish(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.destination.finish(&mut || {
            self.approval.check()?;
            authorized()
        })
    }
    fn cleanup(&mut self) -> io::Result<()> {
        self.destination.cleanup()
    }
}

struct BrowserDataOwner {
    session: Arc<BrowserDataSession>,
    read: Option<FileReadServer>,
    write: Option<FileWriteServer>,
    clipboard: Option<ClipboardServer>,
    clipboard_control: Option<ClipboardServerDeviceControl>,
}
impl HostDataOwner for BrowserDataOwner {
    fn shutdown<'a>(
        &'a mut self,
        reason: StopReason,
    ) -> Pin<Box<dyn Future<Output = Result<(), RemoteError>> + Send + 'a>> {
        Box::pin(async move {
            self.session.retire();
            if let Some(control) = self.clipboard_control.as_ref() {
                control.close_device().map_err(RemoteError::Cleanup)?;
            }
            let read = match self.read.as_mut() {
                Some(server) => Some(server.shutdown(reason).await?),
                None => None,
            };
            if matches!(read, Some(FileShutdown::TimedOut)) {
                return Err(RemoteError::Cleanup(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "browser FileRead cleanup remains pending",
                )));
            }
            if read == Some(FileShutdown::Finished) {
                self.read = None;
            }
            let write = match self.write.as_mut() {
                Some(server) => Some(server.shutdown(reason).await?),
                None => None,
            };
            if matches!(write, Some(FileShutdown::TimedOut)) {
                return Err(RemoteError::Cleanup(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "browser FileWrite cleanup remains pending",
                )));
            }
            if write == Some(FileShutdown::Finished) {
                self.write = None;
            }
            let clipboard = match self.clipboard.as_mut() {
                Some(server) => Some(server.shutdown(reason).await?),
                None => None,
            };
            match clipboard {
                Some(nestlink_remote::clipboard::ClipboardShutdown::Pending) => {
                    return Err(RemoteError::Cleanup(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "browser clipboard cleanup remains pending",
                    )));
                }
                Some(nestlink_remote::clipboard::ClipboardShutdown::Finished) => {
                    self.clipboard = None;
                    self.clipboard_control = None;
                }
                None => {}
            }
            Ok(())
        })
    }
}

pub fn prepare_data_factory(
    registry: Arc<BrowserHostDataRegistry>,
    request_id: &str,
    permit: &VerifiedPermit,
) -> Result<HostDataFactory, BrowserHostError> {
    let binding = nestlink_app_core::browser_host_binding(request_id, permit)?;
    let session = registry.prepare(binding.clone(), permit)?;
    Ok(Box::new(move |claims: HostDataClaims| {
        let expected = session.permitted;
        if !session.active.load(Ordering::Acquire)
            || claims.file_read.is_some() != expected.file_read
            || claims.file_write.is_some() != expected.file_write
            || claims.clipboard.is_some() != (expected.clipboard_read || expected.clipboard_write)
        {
            return Err(WebRtcHostError::Permit);
        }
        let proof_lease = claims
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
        *lock(&session.lease) = Some(proof_lease);
        if let Some(claim) = claims.file_read.as_ref()
            && (claim.generation() != binding.connection_generation
                || claim
                    .lease_control()
                    .check_channel_binding(Channel::FileRead, binding.connection_generation)
                    .is_err())
        {
            return Err(WebRtcHostError::Permit);
        }
        if let Some(claim) = claims.file_write.as_ref()
            && (claim.generation() != binding.connection_generation
                || claim
                    .lease_control()
                    .check_channel_binding(Channel::FileWrite, binding.connection_generation)
                    .is_err())
        {
            return Err(WebRtcHostError::Permit);
        }
        let read = claims
            .file_read
            .map(|claim| {
                FileReadServer::start_claimed(
                    claim,
                    DynamicRead {
                        registry: session.reads.clone(),
                        active: session.active.clone(),
                    },
                )
            })
            .transpose()?;
        let write = claims
            .file_write
            .map(|claim| {
                FileWriteServer::start_claimed(
                    claim,
                    DynamicWrite {
                        registry: session.writes.clone(),
                        active: session.active.clone(),
                    },
                )
            })
            .transpose()?;
        let (clipboard, clipboard_control) = if let Some(transport) = claims.clipboard {
            let expected_binding = WireClipboardBinding {
                session_id: binding.session_id.clone(),
                connection_generation: binding.connection_generation,
            };
            let directions = transport.directions();
            if transport.binding() != &expected_binding
                || directions.read != expected.clipboard_read
                || directions.write != expected.clipboard_write
            {
                return Err(WebRtcHostError::Permit);
            }
            let lease = transport.lease_control();
            let (server, control) =
                ClipboardServer::start_claimed_switchable(transport, directions)?;
            let mut state = lock(&session.clipboard);
            state.lease = Some(lease);
            state.server = Some(control.clone());
            (Some(server), Some(control))
        } else {
            (None, None)
        };
        Ok(Box::new(BrowserDataOwner {
            session,
            read,
            write,
            clipboard,
            clipboard_control,
        }) as Box<dyn HostDataOwner>)
    }))
}

fn open_clipboard(
    binding: &BrowserHostBinding,
    lease: LeaseControl,
    read: bool,
    write: bool,
) -> io::Result<(BrowserClipboardDevice, LocalClipboardApprovalControl)> {
    let wire = WireClipboardBinding {
        session_id: binding.session_id.clone(),
        connection_generation: binding.connection_generation,
    };
    let platform_binding = PlatformClipboardBinding {
        session_id: wire.session_id.clone(),
        connection_generation: wire.connection_generation,
    };
    let (approval, control) =
        LocalClipboardApproval::approve_from_local_user(platform_binding.clone(), read, write)?;
    let authority: Arc<dyn ClipboardAuthority> = Arc::new(BrowserClipboardAuthority {
        lease,
        binding: platform_binding.clone(),
    });
    #[cfg(windows)]
    let platform: Box<dyn PlatformClipboard> = Box::new(
        nestlink_platform_clipboard::WindowsClipboard::open(platform_binding, approval, authority)?,
    );
    #[cfg(target_os = "linux")]
    let platform: Box<dyn PlatformClipboard> = {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Wayland browser clipboard has no matching portal grant",
            ));
        }
        let pid = std::env::var("NESTLINK_LOCAL_GUI_PID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|pid| *pid != 0)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::PermissionDenied, "GUI identity unavailable")
            })?;
        let display = std::env::var("DISPLAY")
            .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "X11 display unavailable"))?;
        Box::new(nestlink_platform_clipboard::X11Clipboard::open_for_desktop(
            &display,
            pid,
            platform_binding,
            approval,
            authority,
        )?)
    };
    #[cfg(not(any(windows, target_os = "linux")))]
    let platform: Box<dyn PlatformClipboard> = {
        let _ = (platform_binding, approval, authority);
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "browser clipboard unavailable on this platform",
        ));
    };
    Ok((
        BrowserClipboardDevice {
            binding: wire,
            platform,
        },
        control,
    ))
}

struct BrowserClipboardAuthority {
    lease: LeaseControl,
    binding: PlatformClipboardBinding,
}
impl ClipboardAuthority for BrowserClipboardAuthority {
    fn check(
        &self,
        binding: &PlatformClipboardBinding,
        direction: PlatformClipboardDirection,
    ) -> io::Result<()> {
        if binding != &self.binding {
            return Err(denied());
        }
        self.lease
            .check_clipboard_binding(
                &binding.session_id,
                match direction {
                    PlatformClipboardDirection::Read => Channel::ClipboardRead,
                    PlatformClipboardDirection::Write => Channel::ClipboardWrite,
                },
                binding.connection_generation,
            )
            .map_err(io::Error::other)
    }
}
struct BrowserClipboardDevice {
    binding: WireClipboardBinding,
    platform: Box<dyn PlatformClipboard>,
}
struct PlatformConsent(nestlink_platform_clipboard::ClipboardDirectionGuard);
impl ClipboardConsent for PlatformConsent {
    fn check_until(&self, deadline: Instant) -> io::Result<()> {
        self.0.check_until(deadline)
    }
}
impl RemoteClipboardDevice for BrowserClipboardDevice {
    fn binding(&self) -> &WireClipboardBinding {
        &self.binding
    }
    fn consent(&self, direction: RemoteClipboardDirection) -> Arc<dyn ClipboardConsent> {
        Arc::new(PlatformConsent(self.platform.direction_guard(
            match direction {
                RemoteClipboardDirection::Read => PlatformClipboardDirection::Read,
                RemoteClipboardDirection::Write => PlatformClipboardDirection::Write,
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
                effect: nestlink_protocol::ClipboardWriteEffect::ClipboardWriteNotApplied,
                error: Some(error),
            };
        }
        match self.platform.write_text(text) {
            Ok(()) => ClipboardWriteOutcome {
                effect: nestlink_protocol::ClipboardWriteEffect::ClipboardWriteApplied,
                error: authorized().err(),
            },
            Err(error) => ClipboardWriteOutcome {
                effect: nestlink_protocol::ClipboardWriteEffect::ClipboardWriteUnknown,
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn binding(request_id: &str) -> BrowserHostBinding {
        BrowserHostBinding {
            request_id: request_id.into(),
            session_id: format!("session-{request_id}"),
            controller_device_id: "controller".into(),
            host_device_id: "host".into(),
            controller_key_sha256: [1; 32],
            host_key_sha256: [2; 32],
            permit_sha256: [3; 32],
            connection_generation: 8,
        }
    }

    fn session(binding: BrowserHostBinding) -> Arc<BrowserDataSession> {
        Arc::new(BrowserDataSession {
            binding,
            permitted: Permitted {
                file_read: true,
                file_write: true,
                clipboard_read: true,
                clipboard_write: true,
            },
            active: Arc::new(AtomicBool::new(true)),
            reads: Arc::new(Mutex::new(BTreeMap::new())),
            writes: Arc::new(Mutex::new(BTreeMap::new())),
            lease: Mutex::new(None),
            clipboard: Mutex::new(ClipboardState {
                server: None,
                lease: None,
                approval: None,
                read: false,
                write: false,
                restart_required: false,
            }),
        })
    }

    #[test]
    fn command_checks_only_its_live_direction_and_revoke_needs_no_channel() {
        assert_eq!(
            required_channels(&BrowserHostDataCommand::SelectReadRoots { roots: Vec::new() }),
            vec![Channel::FileRead]
        );
        assert_eq!(
            required_channels(&BrowserHostDataCommand::SetClipboardDirections {
                read: true,
                write: false,
            }),
            vec![Channel::ClipboardRead]
        );
        assert!(
            required_channels(&BrowserHostDataCommand::RevokeRoot {
                direction: FileDirection::Read,
                root_id: "e7e58d38-16bf-4b95-9b9e-04360c4d5a41".into(),
            })
            .is_empty()
        );
    }

    #[test]
    fn retiring_one_proof_binding_does_not_retire_another_sessions_roots() {
        let old = session(binding("old"));
        let current_binding = binding("current");
        let current = session(current_binding.clone());
        let registry = BrowserHostDataRegistry::default();
        {
            let mut sessions = lock(&registry.sessions);
            sessions.insert(old.binding.clone(), old.clone());
            sessions.insert(current_binding.clone(), current.clone());
        }

        registry.retire_except(Some(&current_binding), None);

        assert!(!old.active.load(Ordering::Acquire));
        assert!(current.active.load(Ordering::Acquire));
        assert!(registry.get(&old.binding).is_none());
        assert!(registry.get(&current_binding).is_some());
    }

    #[test]
    fn a_root_revoked_after_listing_cannot_be_opened_by_a_late_request() {
        let id = "e7e58d38-16bf-4b95-9b9e-04360c4d5a41".to_owned();
        let root_active = Arc::new(AtomicBool::new(true));
        let session_active = Arc::new(AtomicBool::new(true));
        let approval = Arc::new(Approval(vec![session_active, root_active.clone()]));
        let entry = Arc::new(ReadEntry {
            id: id.clone(),
            name: "Documents".into(),
            active: root_active.clone(),
            approval: approval.clone(),
            provider: Mutex::new(ReadProvider {
                path: Some(PathBuf::from("C:\\unopened-test-root")),
                browse: None,
                device: None,
                _read_consent: None,
                _browse_consent: None,
            }),
            _slot: None,
        });
        let registry = Arc::new(Mutex::new(BTreeMap::from([(id.clone(), entry)])));
        let mut device = DynamicRead {
            registry,
            active: Arc::new(AtomicBool::new(true)),
        };
        let listing = device.list_roots(&mut || Ok(())).unwrap();
        assert_eq!(listing.roots[0].root_id, id);
        assert!(listing.consent.check().is_ok());

        root_active.store(false, Ordering::Release);

        assert!(listing.consent.check().is_err());
        assert!(device.open(&id, "private.txt").is_err());
    }

    fn read_selection(directory: &std::path::Path) -> LocalReadRootSelection {
        LocalReadRootSelection {
            directory: directory.to_string_lossy().into_owned(),
            display_name: "Shared folder".into(),
            disclose_directory: true,
        }
    }

    fn write_selection(directory: &std::path::Path) -> LocalWriteRootSelection {
        LocalWriteRootSelection {
            fresh_directory: directory.to_string_lossy().into_owned(),
            display_name: "Receiving folder".into(),
        }
    }

    #[test]
    fn browser_root_reservations_share_daemon_budget_by_direction()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let budget = Arc::new(RootBudget::new(1, 1));
        let quota = Arc::new(WriteQuota::new(FILE_SIZE_BYTES, 1));
        let first_session = session(binding("first"));
        let second_session = session(binding("second"));

        let first_read = build_read_roots(
            &first_session,
            vec![read_selection(directory.path())],
            budget.clone(),
        )?;
        let error = build_read_roots(
            &second_session,
            vec![read_selection(directory.path())],
            budget.clone(),
        )
        .err()
        .ok_or("another browser session must consume the same read-root budget")?;
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);

        let second_write = build_write_roots(
            &second_session,
            vec![write_selection(&directory.path().join("receiving"))],
            budget.clone(),
            quota,
        )?;
        assert_eq!(second_write.len(), 1);
        drop(first_read);

        let replacement_read = build_read_roots(
            &second_session,
            vec![read_selection(directory.path())],
            budget,
        )?;
        assert_eq!(replacement_read.len(), 1);
        Ok(())
    }

    #[test]
    fn browser_read_owner_keeps_revoked_root_slot_until_source_and_browse_drop()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::write(directory.path().join("selected.txt"), b"selected")?;
        let budget = Arc::new(RootBudget::new(1, 1));
        let selected = build_read_roots(
            &session(binding("read-owner")),
            vec![read_selection(directory.path())],
            budget.clone(),
        )?;
        let entry = selected.into_iter().next().ok_or("read root missing")?;
        let id = entry.id.clone();
        let active = entry.active.clone();
        let registry = Arc::new(Mutex::new(BTreeMap::from([(id.clone(), entry.clone())])));
        let mut device = DynamicRead {
            registry: registry.clone(),
            active: Arc::new(AtomicBool::new(true)),
        };
        let mut source = device.open(&id, "selected.txt")?;
        let mut browse = device.browse(&id, &mut || Ok(()))?;
        assert_eq!(browse.begin(None, 1, &mut || Ok(()))?.entries.len(), 1);

        active.store(false, Ordering::Release);
        device.retire_revoked();
        assert!(lock(&registry).is_empty());
        drop(device);
        drop(registry);
        drop(entry);
        assert!(budget.reserve(FileDirection::Read).is_err());
        assert!(source.describe(&mut || Ok(())).is_err());

        drop(source);
        assert!(budget.reserve(FileDirection::Read).is_err());
        drop(browse);
        drop(budget.reserve(FileDirection::Read)?);
        Ok(())
    }

    #[test]
    fn browser_staging_and_native_publication_share_aggregate_write_quota()
    -> Result<(), Box<dyn std::error::Error>> {
        let owner = tempfile::tempdir()?;
        let browser_area = owner.path().join("browser-receiving");
        let native_area = owner.path().join("native-receiving");
        let browser_session = session(binding("write-owner"));
        let root_budget = Arc::new(RootBudget::new(1, 1));
        let quota = Arc::new(WriteQuota::new(4, 1));
        let browser_entry = build_write_roots(
            &browser_session,
            vec![write_selection(&browser_area)],
            root_budget.clone(),
            quota.clone(),
        )?
        .into_iter()
        .next()
        .ok_or("browser write root missing")?;
        let browser_id = browser_entry.id.clone();
        let browser_active = browser_entry.active.clone();
        let registry = Arc::new(Mutex::new(BTreeMap::from([(
            browser_id.clone(),
            browser_entry.clone(),
        )])));
        let mut browser_device = DynamicWrite {
            registry: registry.clone(),
            active: browser_session.active.clone(),
        };
        let native_id = nestlink_auth::random_id();
        let (native_selection, _native_consent) =
            WriteRootSelection::new_with_display_name_and_quota(
                &native_id,
                "Native receiving folder",
                &native_area,
                FILE_SIZE_BYTES,
                quota.clone(),
            )?;
        let mut native_device = WriteRoots::new(vec![native_selection])?;
        let data_sha256 = vec![
            0x3a, 0x6e, 0xb0, 0x79, 0x0f, 0x39, 0xac, 0x87, 0xc9, 0x4f, 0x38, 0x56, 0xb2, 0xdd,
            0x2c, 0x5d, 0x11, 0x0e, 0x68, 0x11, 0x60, 0x22, 0x61, 0xa9, 0xa9, 0x23, 0xd3, 0xbb,
            0x23, 0xad, 0xc8, 0xb7,
        ];
        let open = |root_id: &str, path: &str| FileWriteOpen {
            root_id: root_id.into(),
            path: path.into(),
            size: 4,
            sha256: data_sha256.clone(),
        };

        let mut staged = browser_device.build(&open(&browser_id, "browser.txt"), &mut || Ok(()))?;
        staged.prepare(&mut || Ok(()))?;
        assert_eq!(std::fs::read_dir(&browser_area)?.count(), 1);
        let blocked = native_device
            .build(&open(&native_id, "native.txt"), &mut || Ok(()))
            .err()
            .ok_or("browser staging must reserve the shared bytes and artifact slot")?;
        assert_eq!(blocked.kind(), io::ErrorKind::StorageFull);

        browser_active.store(false, Ordering::Release);
        browser_device.retire_revoked();
        assert!(lock(&registry).is_empty());
        drop(browser_device);
        drop(registry);
        drop(browser_entry);
        assert!(root_budget.reserve(FileDirection::Write).is_err());
        staged.cleanup()?;
        drop(staged);
        drop(root_budget.reserve(FileDirection::Write)?);

        let mut published = native_device.build(&open(&native_id, "native.txt"), &mut || Ok(()))?;
        published.prepare(&mut || Ok(()))?;
        published.write(
            &FileWriteChunk {
                offset: 0,
                data: b"data".to_vec(),
                sha256: data_sha256.clone(),
            },
            &mut || Ok(()),
        )?;
        published.finish(&mut || Ok(()))?;
        assert!(published.status().published);
        assert_eq!(std::fs::read(native_area.join("native.txt"))?, b"data");

        let replacement = build_write_roots(
            &session(binding("write-replacement")),
            vec![write_selection(&browser_area)],
            root_budget,
            quota,
        )?
        .into_iter()
        .next()
        .ok_or("replacement browser write root missing")?;
        let replacement_id = replacement.id.clone();
        let mut replacement_device = DynamicWrite {
            registry: Arc::new(Mutex::new(BTreeMap::from([(
                replacement_id.clone(),
                replacement,
            )]))),
            active: Arc::new(AtomicBool::new(true)),
        };
        let blocked = replacement_device
            .build(&open(&replacement_id, "blocked.txt"), &mut || Ok(()))
            .err()
            .ok_or("published native bytes must remain charged to browser roots")?;
        assert_eq!(blocked.kind(), io::ErrorKind::StorageFull);
        Ok(())
    }
}
