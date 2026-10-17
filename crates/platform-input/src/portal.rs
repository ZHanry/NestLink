//! Explicit Wayland RemoteDesktop/ScreenCast consent and terminal input worker.
//! Permission and epoch authority remain in nestlink-remote. Portal/logind facts
//! only constrain that authority; neither can grant a NestLink business permit.
#![allow(unsafe_code)]
use super::{InputCapabilities, NativeInput, denied};
use crate::keys::linux_evdev;
use futures_util::StreamExt;
use nestlink_platform_clipboard::portal::{
    PortalClipboardGrant, PortalSessionFacts, PreparedPortalClipboard,
};
use nestlink_remote::input::{Button, InputAction, InputDevice, InputLayout, PlatformInput};
use rand_core::{OsRng, RngCore};
use std::{
    collections::{BTreeSet, HashMap},
    io,
    os::fd::OwnedFd,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU8, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, watch};
use zbus::{
    Connection, Proxy,
    connection::Builder,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};

const PORTAL: &str = "org.freedesktop.portal.Desktop";
const ROOT: &str = "/org/freedesktop/portal/desktop";
const REMOTE: &str = "org.freedesktop.portal.RemoteDesktop";
const SCREEN: &str = "org.freedesktop.portal.ScreenCast";
const SESSION: &str = "org.freedesktop.portal.Session";
const REQUEST: &str = "org.freedesktop.portal.Request";
const LOGIN: &str = "org.freedesktop.login1";
const LOGIN_SESSION: &str = "org.freedesktop.login1.Session";
const IPC: Duration = Duration::from_millis(150);
const CONSENT: Duration = Duration::from_secs(300);
const READY: u8 = 1;
const STOPPING: u8 = 2;
const FINISHED: u8 = 3;
type Dict = HashMap<String, OwnedValue>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Control,
    Clipboard,
    View,
}
#[derive(Clone, Copy)]
struct RequestedAccess {
    purpose: Purpose,
    clipboard: bool,
    multiple_sources: bool,
}
impl Purpose {
    fn interface(self) -> &'static str {
        match self {
            Self::Control | Self::Clipboard => REMOTE,
            Self::View => SCREEN,
        }
    }
}

/// This PID must come from the local GUI/its authenticated IPC peer, never from
/// a network request. It identifies the actual Wayland desktop login session.
pub struct PortalOptions {
    pub parent_window: String,
    pub desktop_process_id: u32,
}
impl PortalOptions {
    pub fn current_process(parent_window: String) -> Self {
        Self {
            parent_window,
            desktop_process_id: std::process::id(),
        }
    }
    fn validate(&self) -> io::Result<()> {
        if self.desktop_process_id == 0
            || self.parent_window.len() > 256
            || (!self.parent_window.is_empty()
                && (!self.parent_window.starts_with("wayland:")
                    || self.parent_window[8..].is_empty()
                    || self.parent_window[8..].chars().any(char::is_control)))
        {
            return Err(denied(
                "a local Wayland parent and desktop process are required",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct PortalStream {
    pub node_id: u32,
    /// Stable PipeWire object identity when supplied by the portal. Node IDs can
    /// be reused after destruction; a serial must never fall back to that ID.
    pub pipewire_serial: Option<u64>,
    pub layout: InputLayout,
}
#[derive(Debug, Clone)]
pub struct PortalInfo {
    pub streams: Vec<PortalStream>,
    pub layout: InputLayout,
}
#[derive(Debug)]
pub struct PortalProbe {
    pub remote_desktop_version: u32,
    pub screencast_version: u32,
    pub available_device_types: u32,
}
/// Read OS availability without CreateSession, consent, capture or input.
pub async fn probe() -> io::Result<PortalProbe> {
    let addresses = Addresses::desktop()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let user = until(deadline, bus(&addresses.user, addresses.user_uid)).await?;
    let system = until(deadline, bus(&addresses.system, addresses.system_uid)).await?;
    let result = until(deadline, async {
        let login_owner = owner(&system, LOGIN, addresses.system_uid).await?;
        let manager = proxy(
            &system,
            &login_owner,
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await?;
        let path: OwnedObjectPath = manager
            .call("GetSessionByPID", &(std::process::id(),))
            .await
            .map_err(error)?;
        login_facts(&system, &login_owner, path.as_str(), addresses.user_uid).await?;
        let portal = proxy(&user, PORTAL, ROOT, REMOTE).await?;
        let _: u32 = portal.get_property("version").await.map_err(error)?;
        let pinned = owner(&user, PORTAL, addresses.user_uid).await?;
        let portal = proxy(&user, &pinned, ROOT, REMOTE).await?;
        let remote_desktop_version = portal.get_property("version").await.map_err(error)?;
        let available_device_types = portal
            .get_property("AvailableDeviceTypes")
            .await
            .map_err(error)?;
        let screencast_version = proxy(&user, &pinned, ROOT, SCREEN)
            .await?
            .get_property("version")
            .await
            .map_err(error)?;
        Ok(PortalProbe {
            remote_desktop_version,
            screencast_version,
            available_device_types,
        })
    })
    .await;
    let _ = until(deadline, async { user.close().await.map_err(error) }).await;
    let _ = until(deadline, async { system.close().await.map_err(error) }).await;
    result
}
struct Shared {
    phase: AtomicU8,
    result: Mutex<Option<Result<(), io::ErrorKind>>>,
    ended: Condvar,
    stop: watch::Sender<bool>,
    cleanup_until: Mutex<Option<Instant>>,
}
impl Shared {
    fn stop(&self) {
        self.stop_at(Instant::now() + IPC);
    }
    fn stop_at(&self, until: Instant) {
        if let Ok(mut slot) = self.cleanup_until.lock() {
            *slot = Some(slot.map_or(until, |old| old.min(until)));
        }
        self.phase.fetch_max(STOPPING, Ordering::SeqCst);
        self.stop.send_replace(true);
    }
    fn complete(&self, result: io::Result<()>) {
        if let Ok(mut slot) = self.result.lock() {
            *slot = Some(result.map_err(|e| e.kind()));
        }
        self.phase.store(FINISHED, Ordering::SeqCst);
        self.ended.notify_all();
    }
    fn wait_cleanup(&self, until: Instant) -> io::Result<()> {
        let slot = self
            .result
            .lock()
            .map_err(|_| io::Error::other("portal cleanup state poisoned"))?;
        let (slot, _) = self
            .ended
            .wait_timeout_while(
                slot,
                until.saturating_duration_since(Instant::now()),
                |slot| slot.is_none(),
            )
            .map_err(|_| io::Error::other("portal cleanup state poisoned"))?;
        match *slot {
            Some(Ok(())) => Ok(()),
            Some(Err(kind)) => Err(io::Error::new(kind, "portal cleanup failed")),
            None => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "portal cleanup did not finish within its budget",
            )),
        }
    }
}
/// A media adapter calls invalidate if stream geometry, PipeWire permissions or
/// compositor facts change. This ends the old session; it cannot authorize input.
#[derive(Clone)]
pub struct PortalControl(Arc<Shared>);
impl PortalControl {
    pub fn is_active(&self) -> bool {
        self.0.phase.load(Ordering::SeqCst) == READY
    }
    pub fn invalidate(&self) {
        self.0.stop();
    }
    /// Wait until the original RemoteDesktop owner has finished its real
    /// session-close and D-Bus cleanup path. Dropping a grant is not proof of
    /// that cleanup.
    pub fn wait_closed_until(&self, until: Instant) -> io::Result<()> {
        self.0.wait_cleanup(until)
    }
}
impl PortalSessionFacts for PortalControl {
    fn is_active(&self) -> bool {
        PortalControl::is_active(self)
    }
    fn invalidate(&self) {
        PortalControl::invalidate(self);
    }
    fn wait_closed_until(&self, until: Instant) -> io::Result<()> {
        PortalControl::wait_closed_until(self, until)
    }
}
struct PortalReady {
    info: PortalInfo,
    pipewire: OwnedFd,
    clipboard: Option<PortalClipboardGrant>,
}
enum Operation {
    Input(InputAction),
    Release(Button),
    SelectSource { source: u32, layout: InputLayout },
}
struct Command {
    operation: Operation,
    until: Instant,
    reply: mpsc::SyncSender<io::Result<()>>,
}
pub struct PortalInput {
    info: PortalInfo,
    clipboard: Option<PortalClipboardGrant>,
    pipewire: Option<OwnedFd>,
    shared: Arc<Shared>,
    commands: tokio::sync::mpsc::Sender<Command>,
    worker: Option<thread::JoinHandle<()>>,
    cleanup_until: Option<Instant>,
    purpose: Purpose,
}
/// ScreenCast-only OS consent. This type exposes no input interface and cannot
/// be converted into PortalInput; a later control session needs fresh consent.
pub struct PortalView(PortalInput);
impl PortalView {
    /// Native sessions retain the complete set selected in this one OS dialog.
    pub async fn request_multiple(
        options: PortalOptions,
        mut cancel: watch::Receiver<bool>,
    ) -> io::Result<Self> {
        options.validate()?;
        let addresses = Addresses::desktop()?;
        PortalInput::request_for(
            options,
            addresses,
            &mut cancel,
            RequestedAccess {
                purpose: Purpose::View,
                clipboard: false,
                multiple_sources: true,
            },
        )
        .await
        .map(Self)
    }

    pub async fn request(
        options: PortalOptions,
        mut cancel: watch::Receiver<bool>,
    ) -> io::Result<Self> {
        options.validate()?;
        let addresses = Addresses::desktop()?;
        Self::request_at(options, addresses, &mut cancel).await
    }
    async fn request_at(
        options: PortalOptions,
        addresses: Addresses,
        cancel: &mut watch::Receiver<bool>,
    ) -> io::Result<Self> {
        PortalInput::request_for(
            options,
            addresses,
            cancel,
            RequestedAccess {
                purpose: Purpose::View,
                clipboard: false,
                multiple_sources: false,
            },
        )
        .await
        .map(Self)
    }
    pub fn info(&self) -> &PortalInfo {
        self.0.info()
    }
    pub fn control(&self) -> PortalControl {
        self.0.control()
    }
    pub fn take_pipewire_fd(&mut self) -> io::Result<OwnedFd> {
        self.0.take_pipewire_fd()
    }
    pub fn check(&mut self) -> io::Result<()> {
        self.0.check()
    }
    pub fn close(&mut self) -> io::Result<()> {
        self.0.begin_reset()?;
        self.0.reset()
    }
}
impl PortalInput {
    /// Opens new OS consent every time, with persist_mode=0 and no restore token.
    /// Cancellation/drop closes this request/session and its dedicated bus client.
    pub async fn request(
        options: PortalOptions,
        mut cancel: watch::Receiver<bool>,
    ) -> io::Result<Self> {
        options.validate()?;
        let addresses = Addresses::desktop()?;
        Self::request_at(options, addresses, &mut cancel).await
    }
    /// Extend this new RemoteDesktop consent with Clipboard before Start.
    /// Call only when the local GUI explicitly chose clipboard access. The
    /// resulting grant still needs separately approved read/write directions
    /// and the current NestLink business lease when attached to an adapter.
    pub async fn request_with_clipboard(
        options: PortalOptions,
        mut cancel: watch::Receiver<bool>,
    ) -> io::Result<Self> {
        options.validate()?;
        let addresses = Addresses::desktop()?;
        Self::request_for(
            options,
            addresses,
            &mut cancel,
            RequestedAccess {
                purpose: Purpose::Control,
                clipboard: true,
                multiple_sources: true,
            },
        )
        .await
    }
    /// Opens the original RemoteDesktop capture session with Clipboard access
    /// but without selecting keyboard or pointer devices. Use this when the
    /// connected NestLink session permits clipboard but not remote input.
    pub async fn request_clipboard_capture(
        options: PortalOptions,
        mut cancel: watch::Receiver<bool>,
    ) -> io::Result<Self> {
        options.validate()?;
        let addresses = Addresses::desktop()?;
        Self::request_for(
            options,
            addresses,
            &mut cancel,
            RequestedAccess {
                purpose: Purpose::Clipboard,
                clipboard: true,
                multiple_sources: false,
            },
        )
        .await
    }
    async fn request_at(
        options: PortalOptions,
        addresses: Addresses,
        cancel: &mut watch::Receiver<bool>,
    ) -> io::Result<Self> {
        Self::request_for(
            options,
            addresses,
            cancel,
            RequestedAccess {
                purpose: Purpose::Control,
                clipboard: false,
                multiple_sources: true,
            },
        )
        .await
    }
    async fn request_for(
        options: PortalOptions,
        addresses: Addresses,
        cancel: &mut watch::Receiver<bool>,
        access: RequestedAccess,
    ) -> io::Result<Self> {
        let (stop, stopped) = watch::channel(false);
        let shared = Arc::new(Shared {
            phase: AtomicU8::new(0),
            result: Mutex::new(None),
            ended: Condvar::new(),
            stop,
            cleanup_until: Mutex::new(None),
        });
        let (commands, receiver) = tokio::sync::mpsc::channel(1);
        let (ready, ready_rx) = oneshot::channel();
        let thread_shared = shared.clone();
        let worker = thread::Builder::new()
            .name("nestlink-portal-input".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    runtime.block_on(worker(
                        options,
                        addresses,
                        access,
                        thread_shared.clone(),
                        stopped,
                        receiver,
                        ready,
                    ))
                }))
                .unwrap_or_else(|_| Err(io::Error::other("portal worker panicked")));
                thread_shared.complete(result);
            })?;
        struct CancelOnDrop(Option<Arc<Shared>>);
        impl Drop for CancelOnDrop {
            fn drop(&mut self) {
                if let Some(shared) = &self.0 {
                    shared.stop();
                }
            }
        }
        let mut guard = CancelOnDrop(Some(shared.clone()));
        if *cancel.borrow() || cancel.has_changed().is_err() {
            return Err(denied("portal request cancelled"));
        }
        let result = tokio::select! {biased;_=cancelled(cancel)=>Err(denied("portal request cancelled")),result=ready_rx=>result.map_err(|_| io::Error::other("portal worker ended before consent"))?};
        let PortalReady {
            info,
            pipewire,
            clipboard,
        } = result?;
        // Disarm cancellation only after ownership moves into the adapter.
        guard.0.take();
        Ok(Self {
            info,
            clipboard,
            pipewire: Some(pipewire),
            shared,
            commands,
            worker: Some(worker),
            cleanup_until: None,
            purpose: access.purpose,
        })
    }
    pub fn info(&self) -> &PortalInfo {
        &self.info
    }
    pub fn control(&self) -> PortalControl {
        PortalControl(self.shared.clone())
    }
    /// Transfers the OS grant once. It is bound to this original bus caller,
    /// session and monitored portal/logind facts; no second session is opened.
    pub fn take_clipboard_grant(&mut self) -> io::Result<PortalClipboardGrant> {
        if !self.control().is_active() {
            return Err(denied("portal session ended before clipboard attachment"));
        }
        self.clipboard
            .take()
            .ok_or_else(|| denied("clipboard was not granted or was already transferred"))
    }
    pub fn take_pipewire_fd(&mut self) -> io::Result<OwnedFd> {
        if !self.control().is_active() {
            return Err(denied("portal authority ended before PipeWire transfer"));
        }
        self.pipewire
            .take()
            .ok_or_else(|| denied("PipeWire descriptor already transferred"))
    }
    fn execute(&self, operation: Operation) -> io::Result<()> {
        if self.purpose != Purpose::Control {
            return Err(denied("view-only portal has no input authority"));
        }
        let release = matches!(operation, Operation::Release(_));
        let until = self.cleanup_until.unwrap_or_else(|| Instant::now() + IPC);
        if self.shared.phase.load(Ordering::SeqCst) != READY {
            return if release {
                self.shared.wait_cleanup(until)
            } else {
                Err(denied("portal authority is terminal"))
            };
        }
        let (reply, response) = mpsc::sync_channel(1);
        let result = (|| {
            self.commands
                .try_send(Command {
                    operation,
                    until,
                    reply,
                })
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "portal command queue is unavailable",
                    )
                })?;
            response
                .recv_timeout(until.saturating_duration_since(Instant::now()))
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "portal operation did not finish within its budget",
                    )
                })?
        })();
        if result.is_err() {
            self.shared.stop();
        }
        result
    }
}
impl NativeInput for PortalInput {
    fn layout(&self) -> InputLayout {
        self.info.layout
    }
    fn capabilities(&self) -> InputCapabilities {
        InputCapabilities {
            physical_keys: self.purpose == Purpose::Control,
            pointer_buttons: self.purpose == Purpose::Control,
            text_commit: self.purpose == Purpose::Control,
        }
    }
}
impl InputDevice for PortalInput {
    fn check(&mut self) -> io::Result<()> {
        if self.shared.phase.load(Ordering::SeqCst) != READY {
            return Err(denied("portal or Wayland login permission ended"));
        }
        Ok(())
    }
    fn begin_reset(&mut self) -> io::Result<()> {
        self.cleanup_until = Some(Instant::now() + IPC);
        Ok(())
    }
    fn reset(&mut self) -> io::Result<()> {
        let until = self.cleanup_until.unwrap_or_else(|| Instant::now() + IPC);
        self.shared.stop_at(until);
        let result = self.shared.wait_cleanup(until);
        self.cleanup_until = None;
        result
    }
    fn select_source(&mut self, source: u32, layout: InputLayout) -> io::Result<()> {
        if !self
            .info
            .streams
            .iter()
            .any(|stream| stream.node_id == source && stream.layout == layout)
        {
            return Err(denied("source is outside the existing portal grant"));
        }
        self.execute(Operation::SelectSource { source, layout })
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        match input {
            PlatformInput::Action(action) => self.execute(Operation::Input(action.clone())),
            PlatformInput::Release(button) => self.execute(Operation::Release(button)),
        }
    }
}
impl Drop for PortalInput {
    fn drop(&mut self) {
        let _ = self.begin_reset();
        let _ = self.reset();
        if let Some(worker) = self.worker.take()
            && worker.is_finished()
        {
            let _ = worker.join();
        }
    }
}

struct Addresses {
    user: String,
    system: String,
    user_uid: u32,
    system_uid: u32,
}
impl Addresses {
    fn desktop() -> io::Result<Self> {
        // SAFETY: scalar current effective UID query, no pointers or ownership.
        let uid = unsafe { libc::geteuid() };
        let user = std::env::var("DBUS_SESSION_BUS_ADDRESS")
            .unwrap_or_else(|_| format!("unix:path=/run/user/{uid}/bus"));
        valid_address(&user)?;
        Ok(Self {
            user,
            system: "unix:path=/run/dbus/system_bus_socket".into(),
            user_uid: uid,
            system_uid: 0,
        })
    }
}
fn valid_address(address: &str) -> io::Result<()> {
    if address.len() > 4096
        || address.contains(';')
        || !(address.starts_with("unix:path=/") || address.starts_with("unix:abstract="))
    {
        return Err(denied("portal requires one local Unix D-Bus address"));
    }
    Ok(())
}
fn token() -> String {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut text = String::from("n");
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}
async fn cancelled(receiver: &mut watch::Receiver<bool>) {
    loop {
        if *receiver.borrow() || receiver.changed().await.is_err() {
            return;
        }
    }
}
fn error(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::other(e)
}
async fn until<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "portal IPC budget exhausted before dispatch",
        ));
    }
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "portal IPC budget exhausted"))?
}
async fn bus(address: &str, uid: u32) -> io::Result<Connection> {
    valid_address(address)?;
    let conn = Builder::address(address)
        .map_err(error)?
        .auth_mechanism(zbus::AuthMechanism::External)
        .max_queued(8)
        .method_timeout(Duration::from_secs(2))
        .build()
        .await
        .map_err(error)?;
    if conn.peer_creds().await?.unix_user_id() != Some(uid) {
        let _ = conn.close().await;
        return Err(denied("D-Bus peer does not match the expected OS user"));
    }
    Ok(conn)
}
async fn proxy(
    conn: &Connection,
    destination: &str,
    path: &str,
    interface: &str,
) -> io::Result<Proxy<'static>> {
    Proxy::new(
        conn,
        destination.to_owned(),
        path.to_owned(),
        interface.to_owned(),
    )
    .await
    .map_err(error)
}
async fn owner(conn: &Connection, name: &str, uid: u32) -> io::Result<String> {
    let dbus = proxy(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await?;
    let name: String = dbus.call("GetNameOwner", &(name,)).await.map_err(error)?;
    let owner_uid: u32 = dbus
        .call("GetConnectionUnixUser", &(name.as_str(),))
        .await
        .map_err(error)?;
    if owner_uid != uid || !name.starts_with(':') {
        return Err(denied("OS service owner identity mismatch"));
    }
    Ok(name)
}
fn bounded(message: &zbus::Message) -> io::Result<()> {
    if message.body().len() > 32 * 1024 {
        return Err(denied("OS reply exceeds its decoded message budget"));
    }
    Ok(())
}
async fn login_facts(conn: &Connection, owner: &str, path: &str, uid: u32) -> io::Result<()> {
    let properties = proxy(conn, owner, path, "org.freedesktop.DBus.Properties").await?;
    let reply = properties
        .call_method("GetAll", &(LOGIN_SESSION,))
        .await
        .map_err(error)?;
    bounded(&reply)?;
    let facts: Dict = reply.body().deserialize().map_err(error)?;
    if facts.len() > 64 {
        return Err(denied("login properties exceed budget"));
    }
    let active = bool::try_from(
        facts
            .get("Active")
            .ok_or_else(|| denied("login Active fact unavailable"))?,
    )
    .map_err(error)?;
    let locked = bool::try_from(
        facts
            .get("LockedHint")
            .ok_or_else(|| denied("login lock fact unavailable"))?,
    )
    .map_err(error)?;
    let kind = <&str>::try_from(
        facts
            .get("Type")
            .ok_or_else(|| denied("login type unavailable"))?,
    )
    .map_err(error)?;
    let user: (u32, OwnedObjectPath) = facts
        .get("User")
        .ok_or_else(|| denied("login user unavailable"))?
        .try_clone()
        .map_err(error)?
        .try_into()
        .map_err(error)?;
    if !active || locked || kind != "wayland" || user.0 != uid {
        return Err(denied(
            "Wayland login is locked, inactive or belongs to another user",
        ));
    }
    Ok(())
}
struct Core {
    purpose: Purpose,
    user: Connection,
    system: Connection,
    portal_owner: String,
    login_owner: String,
    login_path: String,
    session: String,
    info: PortalInfo,
    held: BTreeSet<Button>,
    selected_source: Option<u32>,
    symbols: BTreeSet<i32>,
    closed: Option<zbus::proxy::SignalStream<'static>>,
}
struct PortalSetup {
    core: Core,
    pipewire: OwnedFd,
    clipboard: Option<PortalClipboardGrant>,
}
async fn request<'a, B: serde::Serialize + zbus::zvariant::DynamicType>(
    conn: &Connection,
    owner: &str,
    interface: &str,
    method: &str,
    options: HashMap<&'static str, Value<'a>>,
    make_body: impl FnOnce(HashMap<&'static str, Value<'a>>) -> B,
) -> io::Result<Dict> {
    let handle = <&str>::try_from(
        options
            .get("handle_token")
            .ok_or_else(|| denied("request token missing"))?,
    )
    .map_err(error)?
    .to_owned();
    let sender = conn
        .unique_name()
        .ok_or_else(|| denied("bus sender identity missing"))?
        .as_str()
        .trim_start_matches(':')
        .replace('.', "_");
    let expected = format!("/org/freedesktop/portal/desktop/request/{sender}/{handle}");
    let response = proxy(conn, owner, &expected, REQUEST).await?;
    let mut signal = response.receive_signal("Response").await.map_err(error)?;
    let portal = proxy(conn, owner, ROOT, interface).await?;
    let actual: OwnedObjectPath = portal
        .call(method, &make_body(options))
        .await
        .map_err(error)?;
    if actual.as_str() != expected {
        return Err(denied(
            "portal request handle did not match its token and sender",
        ));
    }
    let reply = signal
        .next()
        .await
        .ok_or_else(|| denied("portal response observer ended"))?;
    bounded(&reply)?;
    let (code, results): (u32, Dict) = reply.body().deserialize().map_err(error)?;
    if code != 0 || results.len() > 32 {
        return Err(denied("portal consent cancelled, refused or invalid"));
    }
    Ok(results)
}
fn parse_streams(mut results: Dict, purpose: Purpose) -> io::Result<PortalInfo> {
    if purpose == Purpose::Control {
        let devices = u32::try_from(
            results
                .remove("devices")
                .ok_or_else(|| denied("portal device grant unavailable"))?,
        )
        .map_err(error)?;
        if devices != 3 {
            return Err(denied(
                "the OS did not grant exactly the requested keyboard and pointer",
            ));
        }
    } else if purpose == Purpose::Clipboard {
        if let Some(devices) = results.remove("devices")
            && u32::try_from(devices).map_err(error)? != 0
        {
            return Err(denied(
                "clipboard-only portal unexpectedly granted keyboard or pointer devices",
            ));
        }
    } else if results.contains_key("devices") {
        return Err(denied(
            "screen-only consent unexpectedly includes input devices",
        ));
    }
    let streams: Vec<(u32, Dict)> = results
        .remove("streams")
        .ok_or_else(|| denied("portal stream grant unavailable"))?
        .try_into()
        .map_err(error)?;
    if streams.is_empty() || streams.len() > 64 {
        return Err(denied("portal stream count exceeds budget"));
    }
    let single = streams.len() == 1;
    let mut parsed = Vec::new();
    let mut nodes = BTreeSet::new();
    let mut serials = BTreeSet::new();
    let mut left = i32::MAX;
    let mut top = i32::MAX;
    let mut right = i32::MIN;
    let mut bottom = i32::MIN;
    for (node, mut properties) in streams {
        if node == 0 || node == u32::MAX || !nodes.insert(node) || properties.len() > 32 {
            return Err(denied("invalid or duplicate authorized stream"));
        }
        let pipewire_serial = properties
            .remove("pipewire-serial")
            .map(u64::try_from)
            .transpose()
            .map_err(error)?;
        if pipewire_serial.is_some_and(|serial| serial == 0 || !serials.insert(serial)) {
            return Err(denied("invalid or duplicate authorized stream serial"));
        }
        if u32::try_from(
            properties
                .remove("source_type")
                .ok_or_else(|| denied("stream source type unavailable"))?,
        )
        .map_err(error)?
            != 1
        {
            return Err(denied("absolute input requires an approved monitor stream"));
        }
        let (width, height): (i32, i32) = properties
            .remove("size")
            .ok_or_else(|| denied("logical stream geometry unavailable"))?
            .try_into()
            .map_err(error)?;
        let (x, y): (i32, i32) = match properties.remove("position") {
            Some(value) => value.try_into().map_err(error)?,
            None if single => (0, 0),
            None => return Err(denied("multi-monitor logical positions unavailable")),
        };
        if width <= 0 || height <= 0 || width > 32768 || height > 32768 {
            return Err(denied("logical monitor size exceeds budget"));
        }
        let x2 = x
            .checked_add(width)
            .ok_or_else(|| denied("monitor x overflow"))?;
        let y2 = y
            .checked_add(height)
            .ok_or_else(|| denied("monitor y overflow"))?;
        left = left.min(x);
        top = top.min(y);
        right = right.max(x2);
        bottom = bottom.max(y2);
        parsed.push(PortalStream {
            node_id: node,
            pipewire_serial,
            layout: InputLayout {
                left: x,
                top: y,
                width: width as u32,
                height: height as u32,
            },
        });
    }
    let width = right
        .checked_sub(left)
        .filter(|v| *v <= 32768)
        .ok_or_else(|| denied("logical desktop width exceeds budget"))? as u32;
    let height = bottom
        .checked_sub(top)
        .filter(|v| *v <= 32768)
        .ok_or_else(|| denied("logical desktop height exceeds budget"))? as u32;
    // Mirrored outputs may overlap in compositor coordinates. Either stream
    // maps this same logical point; choose a stable node when routing input.
    parsed.sort_by_key(|stream| stream.node_id);
    Ok(PortalInfo {
        streams: parsed,
        layout: InputLayout {
            left,
            top,
            width,
            height,
        },
    })
}
async fn setup(
    user: &Connection,
    system: &Connection,
    options: &PortalOptions,
    addresses: &Addresses,
    access: RequestedAccess,
    control: PortalControl,
) -> io::Result<PortalSetup> {
    let purpose = access.purpose;
    if access.clipboard && !matches!(purpose, Purpose::Control | Purpose::Clipboard) {
        return Err(denied("clipboard requires explicit RemoteDesktop consent"));
    }
    if purpose == Purpose::Clipboard && !access.clipboard {
        return Err(denied(
            "clipboard-only portal session requires clipboard access",
        ));
    }
    let login_owner = owner(system, LOGIN, addresses.system_uid).await?;
    let manager = proxy(
        system,
        &login_owner,
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )
    .await?;
    let login_path: OwnedObjectPath = manager
        .call("GetSessionByPID", &(options.desktop_process_id,))
        .await
        .map_err(error)?;
    login_facts(
        system,
        &login_owner,
        login_path.as_str(),
        addresses.user_uid,
    )
    .await?;
    // Trigger normal desktop service activation, then pin all work to the
    // resulting unique owner and verify it is this user, including the version.
    let portal = proxy(user, PORTAL, ROOT, purpose.interface()).await?;
    let _: u32 = portal.get_property("version").await.map_err(error)?;
    let portal_owner = owner(user, PORTAL, addresses.user_uid).await?;
    let portal = proxy(user, &portal_owner, ROOT, purpose.interface()).await?;
    let version: u32 = portal.get_property("version").await.map_err(error)?;
    if purpose == Purpose::Clipboard && version == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "RemoteDesktop portal is unavailable for clipboard capture",
        ));
    }
    if purpose == Purpose::Control {
        let devices: u32 = portal
            .get_property("AvailableDeviceTypes")
            .await
            .map_err(error)?;
        if version == 0 || devices & 3 != 3 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "keyboard and pointer portal APIs required",
            ));
        }
    }
    let screen = proxy(user, &portal_owner, ROOT, SCREEN).await?;
    let screen_version: u32 = screen.get_property("version").await.map_err(error)?;
    let cursor_modes: u32 = screen
        .get_property("AvailableCursorModes")
        .await
        .map_err(error)?;
    if screen_version < 3 || cursor_modes & 2 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "monitor portal with embedded cursor mode required",
        ));
    }
    let session_token = token();
    let create_token = token();
    let result = request(
        user,
        &portal_owner,
        purpose.interface(),
        "CreateSession",
        HashMap::from([
            ("handle_token", Value::from(create_token.as_str())),
            ("session_handle_token", Value::from(session_token.as_str())),
        ]),
        |options| (options,),
    )
    .await?;
    let sender = user
        .unique_name()
        .ok_or_else(|| denied("bus sender missing"))?
        .as_str()
        .trim_start_matches(':')
        .replace('.', "_");
    let expected = format!("/org/freedesktop/portal/desktop/session/{sender}/{session_token}");
    let value = result
        .get("session_handle")
        .ok_or_else(|| denied("portal session handle missing"))?;
    // The historical portal contract returns session_handle as a string.
    let session = <&str>::try_from(value).map_err(error)?.to_owned();
    if session != expected {
        return Err(denied(
            "portal session handle did not match its token and sender",
        ));
    }
    let session_path = OwnedObjectPath::try_from(session.as_str()).map_err(error)?;
    // Subscribe before SelectDevices/Start: a rapid OS cancellation can precede
    // the Start reply and must not be lost between consent and the worker loop.
    let session_proxy = proxy(user, &portal_owner, &session, SESSION).await?;
    let closed = session_proxy
        .receive_signal("Closed")
        .await
        .map_err(error)?;
    let prepared_clipboard = if access.clipboard {
        Some(
            PreparedPortalClipboard::request_before_start(
                user,
                &portal_owner,
                session_path.clone(),
                Instant::now() + IPC,
            )
            .await?,
        )
    } else {
        None
    };
    if purpose == Purpose::Control {
        let select_token = token();
        let mut select = HashMap::from([
            ("handle_token", Value::from(select_token.as_str())),
            ("types", Value::from(3u32)),
        ]);
        if version >= 2 {
            select.insert("persist_mode", Value::from(0u32));
        }
        request(
            user,
            &portal_owner,
            REMOTE,
            "SelectDevices",
            select,
            |options| (session_path.clone(), options),
        )
        .await?;
    }
    let source_token = token();
    let mut source_options = HashMap::from([
        ("handle_token", Value::from(source_token.as_str())),
        ("types", Value::from(1u32)),
        ("multiple", Value::from(access.multiple_sources)),
        ("cursor_mode", Value::from(2u32)),
    ]);
    if purpose == Purpose::View && screen_version >= 4 {
        source_options.insert("persist_mode", Value::from(0u32));
    }
    request(
        user,
        &portal_owner,
        SCREEN,
        "SelectSources",
        source_options,
        |options| (session_path.clone(), options),
    )
    .await?;
    let start_token = token();
    let mut result = request(
        user,
        &portal_owner,
        purpose.interface(),
        "Start",
        HashMap::from([("handle_token", Value::from(start_token.as_str()))]),
        |options_map| {
            (
                session_path.clone(),
                options.parent_window.as_str(),
                options_map,
            )
        },
    )
    .await?;
    let clipboard_enabled = if prepared_clipboard.is_some() {
        result
            .remove("clipboard_enabled")
            .map(bool::try_from)
            .transpose()
            .map_err(error)?
            .unwrap_or(false)
    } else {
        false
    };
    let clipboard = prepared_clipboard
        .map(|prepared| prepared.finish_start(clipboard_enabled, Arc::new(control)))
        .transpose()?;
    let info = parse_streams(result, purpose)?;
    let fd: zbus::zvariant::OwnedFd = screen
        .call(
            "OpenPipeWireRemote",
            &(session_path, HashMap::<&str, Value<'_>>::new()),
        )
        .await
        .map_err(error)?;
    login_facts(
        system,
        &login_owner,
        login_path.as_str(),
        addresses.user_uid,
    )
    .await?;
    Ok(PortalSetup {
        core: Core {
            purpose,
            user: user.clone(),
            system: system.clone(),
            portal_owner,
            login_owner,
            login_path: login_path.to_string(),
            session,
            info,
            held: BTreeSet::new(),
            selected_source: None,
            symbols: BTreeSet::new(),
            closed: Some(closed),
        },
        pipewire: fd.into(),
        clipboard,
    })
}
impl Core {
    async fn notify<B: serde::Serialize + zbus::zvariant::DynamicType>(
        &self,
        method: &str,
        body: &B,
    ) -> io::Result<()> {
        proxy(&self.user, &self.portal_owner, ROOT, REMOTE)
            .await?
            .call::<_, _, ()>(method, body)
            .await
            .map_err(error)
    }
    async fn key(&self, key: i32, down: bool) -> io::Result<()> {
        self.notify(
            "NotifyKeyboardKeycode",
            &(
                OwnedObjectPath::try_from(self.session.as_str()).map_err(error)?,
                HashMap::<&str, Value<'_>>::new(),
                key,
                u32::from(down),
            ),
        )
        .await
    }
    async fn button(&self, button: u8, down: bool) -> io::Result<()> {
        let code = match button {
            1 => 0x110,
            2 => 0x111,
            3 => 0x112,
            4 => 0x113,
            5 => 0x114,
            _ => return Err(denied("unknown pointer button")),
        };
        self.notify(
            "NotifyPointerButton",
            &(
                OwnedObjectPath::try_from(self.session.as_str()).map_err(error)?,
                HashMap::<&str, Value<'_>>::new(),
                code,
                u32::from(down),
            ),
        )
        .await
    }
    async fn symbol(&self, symbol: i32, down: bool) -> io::Result<()> {
        self.notify(
            "NotifyKeyboardKeysym",
            &(
                OwnedObjectPath::try_from(self.session.as_str()).map_err(error)?,
                HashMap::<&str, Value<'_>>::new(),
                symbol,
                u32::from(down),
            ),
        )
        .await
    }
    async fn release(&mut self, button: Button) -> io::Result<()> {
        if self.held.contains(&button) {
            match button {
                Button::Key(code) => {
                    self.key(
                        linux_evdev(code).ok_or_else(|| denied("unknown HID usage"))?,
                        false,
                    )
                    .await?
                }
                Button::Pointer(button) => self.button(button, false).await?,
            };
            self.held.remove(&button);
        }
        Ok(())
    }
    async fn operation(&mut self, operation: Operation, uid: u32) -> io::Result<()> {
        if self.purpose != Purpose::Control {
            return Err(denied("screen-only session cannot dispatch input"));
        }
        if let Operation::Release(button) = operation {
            return self.release(button).await;
        }
        login_facts(&self.system, &self.login_owner, &self.login_path, uid).await?;
        let action = match operation {
            Operation::SelectSource { source, layout } => {
                if !self.held.is_empty()
                    || !self.symbols.is_empty()
                    || !self
                        .info
                        .streams
                        .iter()
                        .any(|stream| stream.node_id == source && stream.layout == layout)
                {
                    return Err(denied(
                        "portal source handoff requires released input and the exact grant",
                    ));
                }
                self.selected_source = Some(source);
                return Ok(());
            }
            Operation::Input(action) => action,
            Operation::Release(_) => unreachable!(),
        };
        match action {
            InputAction::Key { code, down } => {
                let key = linux_evdev(code).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Unsupported, "unknown HID usage")
                })?;
                let button = Button::Key(code);
                if down {
                    self.held.insert(button);
                    self.key(key, true).await
                } else {
                    self.release(button).await
                }
            }
            InputAction::Pointer { button, down, x, y } => {
                let stream = self
                    .info
                    .streams
                    .iter()
                    .find(|stream| {
                        // Overlapping portal logical rectangles never select
                        // the first matching display. Native selection pins
                        // the original granted node; legacy single-source
                        // callers may use the sole granted stream.
                        (self.selected_source == Some(stream.node_id)
                            || (self.selected_source.is_none() && self.info.streams.len() == 1))
                            && x >= stream.layout.left
                            && i64::from(x)
                                < i64::from(stream.layout.left) + i64::from(stream.layout.width)
                            && y >= stream.layout.top
                            && i64::from(y)
                                < i64::from(stream.layout.top) + i64::from(stream.layout.height)
                    })
                    .ok_or_else(|| denied("pointer outside an authorized monitor"))?;
                self.notify(
                    "NotifyPointerMotionAbsolute",
                    &(
                        OwnedObjectPath::try_from(self.session.as_str()).map_err(error)?,
                        HashMap::<&str, Value<'_>>::new(),
                        stream.node_id,
                        f64::from(x - stream.layout.left),
                        f64::from(y - stream.layout.top),
                    ),
                )
                .await?;
                if let Some(button) = button {
                    if down {
                        self.held.insert(Button::Pointer(button));
                        self.button(button, true).await?;
                    } else {
                        self.release(Button::Pointer(button)).await?;
                    }
                }
                Ok(())
            }
            InputAction::Text(text) => {
                if text.is_empty() || text.len() > 16384 || !self.held.is_empty() {
                    return Err(denied(
                        "text requires released buttons and a bounded message",
                    ));
                }
                for character in text.chars() {
                    let symbol = match character {
                        '\n' => 0xff0d,
                        '\t' => 0xff09,
                        c if c.is_control() => return Err(denied("unsupported control character")),
                        c if u32::from(c) <= 0xff => u32::from(c) as i32,
                        c => (0x01000000 | u32::from(c)) as i32,
                    };
                    self.symbols.insert(symbol);
                    self.symbol(symbol, true).await?;
                    self.symbol(symbol, false).await?;
                    self.symbols.remove(&symbol);
                }
                Ok(())
            }
        }
    }
    async fn cleanup(&mut self) -> io::Result<()> {
        let mut first = None;
        for button in self.held.iter().copied().collect::<Vec<_>>() {
            if let Err(e) = self.release(button).await
                && first.is_none()
            {
                first = Some(e);
            }
        }
        for symbol in self.symbols.iter().copied().collect::<Vec<_>>() {
            match self.symbol(symbol, false).await {
                Ok(()) => {
                    self.symbols.remove(&symbol);
                }
                Err(e) => {
                    if first.is_none() {
                        first = Some(e);
                    }
                }
            }
        }
        let closed = proxy(&self.user, &self.portal_owner, &self.session, SESSION)
            .await?
            .call::<_, _, ()>("Close", &())
            .await
            .map_err(error);
        if first.is_none() {
            first = closed.err();
        }
        first.map_or(Ok(()), Err)
    }
}
async fn worker(
    options: PortalOptions,
    addresses: Addresses,
    access: RequestedAccess,
    shared: Arc<Shared>,
    mut stop: watch::Receiver<bool>,
    mut commands: tokio::sync::mpsc::Receiver<Command>,
    ready: oneshot::Sender<io::Result<PortalReady>>,
) -> io::Result<()> {
    let connect = Instant::now() + Duration::from_secs(2);
    let user = match until(connect, bus(&addresses.user, addresses.user_uid)).await {
        Ok(user) => user,
        Err(e) => {
            let _ = ready.send(Err(io::Error::new(e.kind(), e.to_string())));
            return Err(e);
        }
    };
    let system = match until(connect, bus(&addresses.system, addresses.system_uid)).await {
        Ok(system) => system,
        Err(e) => {
            let _ = until(connect, async { user.close().await.map_err(error) }).await;
            let _ = ready.send(Err(io::Error::new(e.kind(), e.to_string())));
            return Err(e);
        }
    };
    let setup = tokio::select! {biased;_=stop.changed()=>Err(denied("portal consent cancelled")),result=until(Instant::now()+CONSENT,setup(&user,&system,&options,&addresses,access,PortalControl(shared.clone())))=>result};
    let PortalSetup {
        mut core,
        pipewire: fd,
        clipboard,
    } = match setup {
        Ok(value) => value,
        Err(e) => {
            let _ = user.close().await;
            let _ = system.close().await;
            let _ = ready.send(Err(io::Error::new(e.kind(), e.to_string())));
            return Err(e);
        }
    };
    let mut monitors = Vec::new();
    let mut closed = core
        .closed
        .take()
        .ok_or_else(|| denied("portal closed observer missing"))?;
    let watched = shared.clone();
    monitors.push(tokio::spawn(async move {
        let _ = closed.next().await;
        watched.stop();
    }));
    for (conn, name, unique) in [
        (&user, PORTAL, core.portal_owner.as_str()),
        (&system, LOGIN, core.login_owner.as_str()),
    ] {
        let dbus = proxy(
            conn,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .await?;
        let mut changed = dbus
            .receive_signal_with_args("NameOwnerChanged", &[(0, name)])
            .await
            .map_err(error)?;
        let original = unique.to_owned();
        let watched = shared.clone();
        monitors.push(tokio::spawn(async move {
            while let Some(message) = changed.next().await {
                let Ok((_, old, new)) = message.body().deserialize::<(String, String, String)>()
                else {
                    break;
                };
                if old == original || new != original {
                    break;
                }
            }
            watched.stop();
        }));
        // Recheck after installing match rules to close the subscription race.
        if owner(
            conn,
            name,
            if name == PORTAL {
                addresses.user_uid
            } else {
                addresses.system_uid
            },
        )
        .await?
            != unique
        {
            shared.stop();
        }
    }
    let properties = proxy(
        &system,
        &core.login_owner,
        &core.login_path,
        "org.freedesktop.DBus.Properties",
    )
    .await?;
    let mut changed = properties
        .receive_signal_with_args("PropertiesChanged", &[(0, LOGIN_SESSION)])
        .await
        .map_err(error)?;
    let watched = shared.clone();
    monitors.push(tokio::spawn(async move {
        while let Some(message) = changed.next().await {
            if bounded(&message).is_err() {
                break;
            }
            let Ok((_, values, invalid)) =
                message.body().deserialize::<(String, Dict, Vec<String>)>()
            else {
                break;
            };
            if values.len() > 64
                || invalid.len() > 64
                || ["Active", "LockedHint", "Type", "User"]
                    .iter()
                    .any(|key| values.contains_key(*key) || invalid.iter().any(|v| v == key))
            {
                break;
            }
        }
        watched.stop();
    }));
    login_facts(
        &system,
        &core.login_owner,
        &core.login_path,
        addresses.user_uid,
    )
    .await?;
    if *stop.borrow() {
        shared.stop();
    } else {
        let _ = shared
            .phase
            .compare_exchange(0, READY, Ordering::SeqCst, Ordering::SeqCst);
    }
    let activated = if shared.phase.load(Ordering::SeqCst) == READY {
        Ok(PortalReady {
            info: core.info.clone(),
            pipewire: fd,
            clipboard,
        })
    } else {
        Err(denied("OS consent ended before input became available"))
    };
    if ready.send(activated).is_err() {
        shared.stop();
    }
    let mut poll = tokio::time::interval(Duration::from_millis(250));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if *stop.borrow() || shared.phase.load(Ordering::SeqCst) != READY {
            break;
        }
        tokio::select! {biased;
            _=stop.changed()=>break,
            _=poll.tick()=>{let result=tokio::select! {biased;_=stop.changed()=>Err(denied("portal cancelled")),result=until(Instant::now()+IPC,login_facts(&system,&core.login_owner,&core.login_path,addresses.user_uid))=>result};if result.is_err(){break;}},
            command=commands.recv()=>{
                let Some(command)=command else {break;};
                let result=tokio::select! {biased;_=stop.changed()=>Err(denied("portal cancelled")),result=until(command.until,core.operation(command.operation,addresses.user_uid))=>result};
                let failed=result.is_err();let _=command.reply.send(result);if failed{break;}
            }
        }
    }
    shared.stop();
    commands.close();
    let cleanup_until = shared
        .cleanup_until
        .lock()
        .ok()
        .and_then(|value| *value)
        .unwrap_or_else(|| Instant::now() + IPC);
    let result = until(cleanup_until, core.cleanup()).await;
    for monitor in monitors {
        monitor.abort();
    }
    let _ = until(cleanup_until, async { user.close().await.map_err(error) }).await;
    let _ = until(cleanup_until, async { system.close().await.map_err(error) }).await;
    result
}

#[cfg(test)]
mod tests;
