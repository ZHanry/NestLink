use super::Result;
use std::{
    collections::HashMap,
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::sync::{oneshot, watch};
use zbus::{
    Connection,
    connection::Builder,
    interface,
    message::Header,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};

const ROOT: &str = "/org/freedesktop/portal/desktop";
const PORTAL: &str = "org.freedesktop.portal.Desktop";
const LOGIN: &str = "org.freedesktop.login1";
const LOGIN_PATH: &str = "/org/freedesktop/login1/session/owned";
type Dict = HashMap<String, OwnedValue>;

#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    RemoteCreate,
    ScreenCreate,
    RemoteStart,
    ScreenStart,
    Devices(u32, u32),
    Sources(u32, Option<u32>),
    OpenFd,
    Key(i32, u32),
    Symbol(i32, u32),
    Button(i32, u32),
    Motion(u32, f64, f64),
    Close,
}
struct State {
    events: Mutex<Vec<Event>>,
    locked: AtomicBool,
    closed: AtomicBool,
    socket: PathBuf,
    invalid_fd: bool,
    node: u32,
    serial: u64,
}
impl State {
    fn event(&self, event: Event) -> zbus::fdo::Result<()> {
        self.events
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("fixture poisoned".into()))?
            .push(event);
        Ok(())
    }
    fn metadata(&self) -> Dict {
        HashMap::from([
            ("size".into(), value((320i32, 240i32))),
            ("position".into(), value((-320i32, 0i32))),
            ("source_type".into(), value(1u32)),
            ("pipewire-serial".into(), value(self.serial)),
        ])
    }
}
fn value(v: impl Into<Value<'static>>) -> OwnedValue {
    OwnedValue::try_from(v.into()).unwrap_or_else(|e| panic!("fixture value: {e}"))
}
fn string(options: &Dict, key: &str) -> zbus::fdo::Result<String> {
    options
        .get(key)
        .and_then(|v| <&str>::try_from(v).ok())
        .map(str::to_owned)
        .ok_or_else(|| zbus::fdo::Error::InvalidArgs(format!("missing {key}")))
}
fn number(options: &Dict, key: &str) -> zbus::fdo::Result<u32> {
    options
        .get(key)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| zbus::fdo::Error::InvalidArgs(format!("missing {key}")))
}
fn client(header: &Header<'_>) -> zbus::fdo::Result<String> {
    header
        .sender()
        .map(|v| v.as_str().to_owned())
        .ok_or_else(|| zbus::fdo::Error::AccessDenied("sender missing".into()))
}
async fn response(
    conn: &Connection,
    header: &Header<'_>,
    options: Dict,
    results: Dict,
) -> zbus::fdo::Result<OwnedObjectPath> {
    let caller = client(header)?;
    let sender = caller.trim_start_matches(':').replace('.', "_");
    let token = string(&options, "handle_token")?;
    let path = format!("{ROOT}/request/{sender}/{token}");
    conn.emit_signal(
        Some(caller.as_str()),
        path.as_str(),
        "org.freedesktop.portal.Request",
        "Response",
        &(0u32, results),
    )
    .await
    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
    OwnedObjectPath::try_from(path).map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))
}
async fn create(
    state: &Arc<State>,
    options: Dict,
    header: Header<'_>,
    conn: &Connection,
) -> zbus::fdo::Result<OwnedObjectPath> {
    let sender = client(&header)?.trim_start_matches(':').replace('.', "_");
    let token = string(&options, "session_handle_token")?;
    let path = format!("{ROOT}/session/{sender}/{token}");
    conn.object_server()
        .at(path.as_str(), Session(state.clone()))
        .await
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
    response(
        conn,
        &header,
        options,
        HashMap::from([("session_handle".into(), value(path))]),
    )
    .await
}
struct Remote(Arc<State>);
#[interface(name = "org.freedesktop.portal.RemoteDesktop")]
impl Remote {
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        2
    }
    #[zbus(property)]
    fn available_device_types(&self) -> u32 {
        3
    }
    async fn create_session(
        &self,
        options: Dict,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        self.0.event(Event::RemoteCreate)?;
        create(&self.0, options, header, conn).await
    }
    async fn select_devices(
        &self,
        _session: OwnedObjectPath,
        options: Dict,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        let devices = number(&options, "types")?;
        let persist = number(&options, "persist_mode")?;
        if devices != 3 || persist != 0 || options.contains_key("restore_token") {
            return Err(zbus::fdo::Error::InvalidArgs(
                "fresh control consent required".into(),
            ));
        }
        self.0.event(Event::Devices(devices, persist))?;
        response(conn, &header, options, Dict::new()).await
    }
    async fn start(
        &self,
        _session: OwnedObjectPath,
        _parent: String,
        options: Dict,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        self.0.event(Event::RemoteStart)?;
        response(
            conn,
            &header,
            options,
            HashMap::from([
                ("devices".into(), value(3u32)),
                (
                    "streams".into(),
                    value(vec![(self.0.node, self.0.metadata())]),
                ),
            ]),
        )
        .await
    }
    fn notify_keyboard_keycode(
        &self,
        _session: OwnedObjectPath,
        _options: Dict,
        key: i32,
        state: u32,
    ) -> zbus::fdo::Result<()> {
        if self.0.closed.load(Ordering::SeqCst) {
            return Err(zbus::fdo::Error::AccessDenied("closed".into()));
        }
        self.0.event(Event::Key(key, state))
    }
    fn notify_keyboard_keysym(
        &self,
        _session: OwnedObjectPath,
        _options: Dict,
        key: i32,
        state: u32,
    ) -> zbus::fdo::Result<()> {
        self.0.event(Event::Symbol(key, state))
    }
    fn notify_pointer_button(
        &self,
        _session: OwnedObjectPath,
        _options: Dict,
        button: i32,
        state: u32,
    ) -> zbus::fdo::Result<()> {
        self.0.event(Event::Button(button, state))
    }
    fn notify_pointer_motion_absolute(
        &self,
        _session: OwnedObjectPath,
        _options: Dict,
        node: u32,
        x: f64,
        y: f64,
    ) -> zbus::fdo::Result<()> {
        self.0.event(Event::Motion(node, x, y))
    }
}
struct Screen(Arc<State>);
#[interface(name = "org.freedesktop.portal.ScreenCast")]
impl Screen {
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        6
    }
    #[zbus(property)]
    fn available_cursor_modes(&self) -> u32 {
        3
    }
    async fn create_session(
        &self,
        options: Dict,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        self.0.event(Event::ScreenCreate)?;
        create(&self.0, options, header, conn).await
    }
    async fn start(
        &self,
        _session: OwnedObjectPath,
        _parent: String,
        options: Dict,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        self.0.event(Event::ScreenStart)?;
        response(
            conn,
            &header,
            options,
            HashMap::from([(
                "streams".into(),
                value(vec![(self.0.node, self.0.metadata())]),
            )]),
        )
        .await
    }
    async fn select_sources(
        &self,
        _session: OwnedObjectPath,
        options: Dict,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        let cursor = number(&options, "cursor_mode")?;
        let persist = options
            .get("persist_mode")
            .map(u32::try_from)
            .transpose()
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        if cursor != 2 || persist.is_some_and(|p| p != 0) || options.contains_key("restore_token") {
            return Err(zbus::fdo::Error::InvalidArgs(
                "fresh embedded-cursor consent required".into(),
            ));
        }
        self.0.event(Event::Sources(cursor, persist))?;
        response(conn, &header, options, Dict::new()).await
    }
    fn open_pipe_wire_remote(
        &self,
        _session: OwnedObjectPath,
        _options: Dict,
    ) -> zbus::fdo::Result<zbus::zvariant::OwnedFd> {
        self.0.event(Event::OpenFd)?;
        if self.0.invalid_fd {
            let file = std::fs::File::open("/dev/null")
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
            return Ok(OwnedFd::from(file).into());
        }
        let socket = UnixStream::connect(&self.0.socket)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(OwnedFd::from(socket).into())
    }
}
struct Session(Arc<State>);
#[interface(name = "org.freedesktop.portal.Session")]
impl Session {
    fn close(&self) -> zbus::fdo::Result<()> {
        self.0.closed.store(true, Ordering::SeqCst);
        self.0.event(Event::Close)
    }
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        1
    }
}
struct LoginManager;
#[interface(name = "org.freedesktop.login1.Manager")]
impl LoginManager {
    #[zbus(name = "GetSessionByPID")]
    fn get_session_by_pid(&self, _pid: u32) -> zbus::fdo::Result<OwnedObjectPath> {
        OwnedObjectPath::try_from(LOGIN_PATH).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }
}
struct LoginSession(Arc<State>);
#[interface(name = "org.freedesktop.login1.Session")]
impl LoginSession {
    #[zbus(property)]
    fn active(&self) -> bool {
        true
    }
    #[zbus(property)]
    fn locked_hint(&self) -> bool {
        self.0.locked.load(Ordering::SeqCst)
    }
    #[zbus(property, name = "Type")]
    fn kind(&self) -> &str {
        "wayland"
    }
    #[zbus(property)]
    fn user(&self) -> (u32, OwnedObjectPath) {
        (
            0,
            OwnedObjectPath::try_from("/org/freedesktop/login1/user/owned")
                .unwrap_or_else(|e| panic!("fixture path: {e}")),
        )
    }
}
pub struct Service {
    state: Arc<State>,
    system: Connection,
    shutdown: watch::Sender<bool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Service {
    pub async fn new(socket: PathBuf, node: u32, serial: u64, control: bool) -> Result<Self> {
        Self::start(socket, node, serial, control, false).await
    }
    pub async fn invalid_fd(
        socket: PathBuf,
        node: u32,
        serial: u64,
        control: bool,
    ) -> Result<Self> {
        Self::start(socket, node, serial, control, true).await
    }
    async fn start(
        socket: PathBuf,
        node: u32,
        serial: u64,
        control: bool,
        invalid_fd: bool,
    ) -> Result<Self> {
        let state = Arc::new(State {
            events: Mutex::new(vec![]),
            locked: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            socket,
            invalid_fd,
            node,
            serial,
        });
        let services = state.clone();
        let address = std::env::var("DBUS_SESSION_BUS_ADDRESS")?;
        let (shutdown, mut stopped) = watch::channel(false);
        let (ready, result) = oneshot::channel();
        // The server runs separately from synchronous InputController calls and
        // the application's lease supervisor, as real OS services would.
        let worker = thread::spawn(move || {
            let outcome = (|| -> Result {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(async {
                    let mut builder = Builder::address(address.as_str())?
                        .name(PORTAL)?
                        .serve_at(ROOT, Screen(services.clone()))?;
                    if control {
                        builder = builder.serve_at(ROOT, Remote(services.clone()))?;
                    }
                    let portal = builder.build().await?;
                    let system = Builder::address("unix:path=/run/dbus/system_bus_socket")?
                        .name(LOGIN)?
                        .serve_at("/org/freedesktop/login1", LoginManager)?
                        .serve_at(LOGIN_PATH, LoginSession(services))?
                        .build()
                        .await?;
                    let _ = ready.send(system.clone());
                    let _ = stopped.changed().await;
                    let _ = tokio::time::timeout(Duration::from_millis(100), portal.close()).await;
                    let _ = tokio::time::timeout(Duration::from_millis(100), system.close()).await;
                    Ok(())
                })
            })();
            assert!(outcome.is_ok(), "owned service failed: {outcome:?}");
        });
        let system = tokio::time::timeout(Duration::from_secs(2), result).await??;
        Ok(Self {
            state,
            system,
            shutdown,
            worker: Some(worker),
        })
    }
    pub fn events(&self) -> Result<Vec<Event>> {
        Ok(self
            .state
            .events
            .lock()
            .map_err(|_| "fixture poisoned")?
            .clone())
    }
    pub async fn lock(&self) -> Result {
        self.state.locked.store(true, Ordering::SeqCst);
        self.system
            .emit_signal(
                None::<&str>,
                LOGIN_PATH,
                "org.freedesktop.DBus.Properties",
                "PropertiesChanged",
                &(
                    "org.freedesktop.login1.Session",
                    HashMap::from([("LockedHint", value(true))]),
                    Vec::<String>::new(),
                ),
            )
            .await?;
        Ok(())
    }
    pub fn unlock(&self) {
        self.state.locked.store(false, Ordering::SeqCst);
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
