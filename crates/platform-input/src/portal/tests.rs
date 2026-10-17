//! Private D-Bus contract fixtures. These never claim compositor/IME acceptance.
use super::*;
use nestlink_platform_clipboard::{
    ClipboardAuthority, ClipboardBinding, ClipboardDirection, LocalClipboardApproval,
    NativeClipboard, portal::PortalClipboard,
};
use nestlink_remote::{
    CleanupStatus,
    input::{InputController, InputEpoch, InputEvent},
};
use nestlink_session::StopReason;
use std::{
    io::{Read, Seek, SeekFrom, Write},
    os::fd::AsRawFd,
    process::{Child, Command as Process, Stdio},
    sync::atomic::{AtomicBool, AtomicU32},
};
use zbus::{interface, message::Header};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const LOGIN_PATH: &str = "/org/freedesktop/login1/session/test";
#[derive(Debug, Clone, PartialEq)]
enum Event {
    Key(i32, u32),
    Symbol(i32, u32),
    Button(i32, u32),
    Motion(u32, f64, f64),
    Close,
    Devices(u32, u32),
    RemoteCreate,
    RemoteStart,
    ClipboardRequest,
    ClipboardRead,
    ScreenCreate,
    ScreenStart,
    Sources(u32, Option<u32>),
}
#[derive(Default)]
struct State {
    events: Mutex<Vec<Event>>,
    session: Mutex<String>,
    caller: Mutex<String>,
    locked: AtomicBool,
    closed: AtomicBool,
    mode: AtomicU32,
    waiting: AtomicBool,
    clipboard_requested: AtomicBool,
    started: AtomicBool,
}
impl State {
    fn event(&self, event: Event) -> zbus::fdo::Result<()> {
        self.events
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("fixture poisoned".into()))?
            .push(event);
        Ok(())
    }
}
struct Bus {
    child: Child,
    _directory: tempfile::TempDir,
    address: String,
}
impl Bus {
    fn new() -> io::Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("nestlink-portal-")
            .tempdir()?;
        let address = format!("unix:path={}", directory.path().join("bus").display());
        let mut child = Process::new("dbus-daemon")
            .args([
                "--session",
                "--nofork",
                "--print-address=1",
                "--address",
                &address,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let ready = (|| {
            let stdout = child
                .stdout
                .as_mut()
                .ok_or_else(|| io::Error::other("bus readiness pipe missing"))?;
            // SAFETY: borrowed owned child pipe; only nonblocking status is changed.
            if unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut bytes = Vec::new();
            while !bytes.contains(&b'\n') {
                if Instant::now() >= deadline || bytes.len() > 4096 {
                    return Err(io::Error::other("owned D-Bus daemon did not become ready"));
                }
                let mut buffer = [0; 256];
                match stdout.read(&mut buffer) {
                    Ok(0) => return Err(io::Error::other("owned D-Bus daemon exited")),
                    Ok(n) => bytes.extend_from_slice(&buffer[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        })();
        if let Err(e) = ready {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        Ok(Self {
            child,
            _directory: directory,
            address,
        })
    }
}
impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn value(value: impl Into<Value<'static>>) -> OwnedValue {
    OwnedValue::try_from(value.into()).unwrap_or_else(|e| panic!("fixture value: {e}"))
}
fn string(options: &Dict, key: &str) -> zbus::fdo::Result<String> {
    options
        .get(key)
        .and_then(|v| <&str>::try_from(v).ok())
        .map(str::to_owned)
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
    code: u32,
    results: Dict,
) -> zbus::fdo::Result<OwnedObjectPath> {
    let caller = client(header)?;
    let sender = caller.trim_start_matches(':').replace('.', "_");
    let token = string(&options, "handle_token")?;
    let path = format!("{ROOT}/request/{sender}/{token}");
    conn.emit_signal(
        Some(caller.as_str()),
        path.as_str(),
        REQUEST,
        "Response",
        &(code, results),
    )
    .await
    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
    OwnedObjectPath::try_from(path).map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))
}
async fn create_session(
    state: &Arc<State>,
    options: Dict,
    header: Header<'_>,
    conn: &Connection,
) -> zbus::fdo::Result<OwnedObjectPath> {
    let caller = client(&header)?;
    let sender = caller.trim_start_matches(':').replace('.', "_");
    let token = string(&options, "session_handle_token")?;
    let path = format!("{ROOT}/session/{sender}/{token}");
    *state
        .session
        .lock()
        .map_err(|_| zbus::fdo::Error::Failed("fixture poisoned".into()))? = path.clone();
    *state
        .caller
        .lock()
        .map_err(|_| zbus::fdo::Error::Failed("fixture poisoned".into()))? = caller;
    conn.object_server()
        .at(path.as_str(), Session(state.clone()))
        .await
        .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
    response(
        conn,
        &header,
        options,
        0,
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
        create_session(&self.0, options, header, conn).await
    }
    async fn select_devices(
        &self,
        _session: OwnedObjectPath,
        options: Dict,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        let types = u32::try_from(
            options
                .get("types")
                .ok_or_else(|| zbus::fdo::Error::InvalidArgs("types missing".into()))?,
        )
        .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        let persist = u32::try_from(
            options
                .get("persist_mode")
                .ok_or_else(|| zbus::fdo::Error::InvalidArgs("persist mode missing".into()))?,
        )
        .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        self.0.event(Event::Devices(types, persist))?;
        if options.contains_key("restore_token") {
            return Err(zbus::fdo::Error::InvalidArgs(
                "must not restore old consent".into(),
            ));
        }
        response(conn, &header, options, 0, Dict::new()).await
    }
    async fn start(
        &self,
        session: OwnedObjectPath,
        _parent: String,
        options: Dict,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        self.0.event(Event::RemoteStart)?;
        self.0.started.store(true, Ordering::SeqCst);
        if self.0.mode.load(Ordering::SeqCst) == 4 {
            self.0.waiting.store(true, Ordering::SeqCst);
            let caller = client(&header)?;
            let sender = caller.trim_start_matches(':').replace('.', "_");
            let token = string(&options, "handle_token")?;
            return OwnedObjectPath::try_from(format!("{ROOT}/request/{sender}/{token}"))
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()));
        }
        if self.0.mode.load(Ordering::SeqCst) == 1 {
            return response(conn, &header, options, 1, Dict::new()).await;
        }
        if self.0.mode.load(Ordering::SeqCst) == 2 {
            conn.emit_signal(
                Some(client(&header)?.as_str()),
                session.as_str(),
                SESSION,
                "Closed",
                &(Dict::new(),),
            )
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        }
        let metadata = HashMap::from([
            ("size".to_owned(), value((1024i32, 768i32))),
            ("position".to_owned(), value((-1024i32, 0i32))),
            ("source_type".to_owned(), value(1u32)),
        ]);
        let mut streams = vec![(42u32, metadata)];
        if self.0.mode.load(Ordering::SeqCst) == 12 {
            // Equal rectangles are legal portal grants; only the selected
            // original node, never the first geometry match, owns pointer input.
            streams.push((
                77u32,
                HashMap::from([
                    ("size".to_owned(), value((1024i32, 768i32))),
                    ("position".to_owned(), value((-1024i32, 0i32))),
                    ("source_type".to_owned(), value(1u32)),
                ]),
            ));
        }
        let mut results = HashMap::from([
            (
                "devices".to_owned(),
                value(if self.0.mode.load(Ordering::SeqCst) == 5 {
                    1u32
                } else {
                    3u32
                }),
            ),
            ("streams".to_owned(), value(streams)),
        ]);
        if self.0.clipboard_requested.load(Ordering::SeqCst) {
            match self.0.mode.load(Ordering::SeqCst) {
                10 => {} // omission is not a grant
                11 => {
                    results.insert("clipboard_enabled".into(), value("true"));
                }
                mode => {
                    results.insert("clipboard_enabled".into(), value(mode != 9));
                }
            }
        }
        response(conn, &header, options, 0, results).await
    }
    async fn notify_keyboard_keycode(
        &self,
        _session: OwnedObjectPath,
        _options: Dict,
        key: i32,
        state: u32,
    ) -> zbus::fdo::Result<()> {
        if self.0.mode.load(Ordering::SeqCst) == 3 && state == 1 {
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        if self.0.closed.load(Ordering::SeqCst) {
            return Err(zbus::fdo::Error::AccessDenied("session closed".into()));
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
struct ClipboardExtension(Arc<State>);
impl ClipboardExtension {
    fn verify(&self, session: &OwnedObjectPath, header: &Header<'_>) -> zbus::fdo::Result<()> {
        let original = self
            .0
            .session
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("fixture poisoned".into()))?;
        let caller = self
            .0
            .caller
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("fixture poisoned".into()))?;
        if original.as_str() != session.as_str() || caller.as_str() != client(header)? {
            return Err(zbus::fdo::Error::AccessDenied(
                "not the original session and caller".into(),
            ));
        }
        Ok(())
    }
}
#[interface(name = "org.freedesktop.portal.Clipboard")]
impl ClipboardExtension {
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        1
    }
    fn request_clipboard(
        &self,
        session: OwnedObjectPath,
        _options: Dict,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        self.verify(&session, &header)?;
        if self.0.started.load(Ordering::SeqCst) {
            return Err(zbus::fdo::Error::AccessDenied(
                "clipboard requested after Start".into(),
            ));
        }
        self.0.clipboard_requested.store(true, Ordering::SeqCst);
        self.0.event(Event::ClipboardRequest)
    }
    fn selection_read(
        &self,
        session: OwnedObjectPath,
        mime: String,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<zbus::zvariant::OwnedFd> {
        self.verify(&session, &header)?;
        if !self.0.clipboard_requested.load(Ordering::SeqCst)
            || !self.0.started.load(Ordering::SeqCst)
            || self.0.closed.load(Ordering::SeqCst)
            || mime != "text/plain;charset=utf-8"
        {
            return Err(zbus::fdo::Error::AccessDenied(
                "clipboard session is not granted".into(),
            ));
        }
        self.0.event(Event::ClipboardRead)?;
        let mut file = tempfile::tempfile().map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        file.write_all("original caller fixture 中文🙂".as_bytes())
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(OwnedFd::from(file).into())
    }
}
struct Screen(Arc<State>);
#[interface(name = "org.freedesktop.portal.ScreenCast")]
impl Screen {
    #[zbus(property, name = "version")]
    fn version(&self) -> u32 {
        if self.0.mode.load(Ordering::SeqCst) == 6 {
            3
        } else if self.0.mode.load(Ordering::SeqCst) == 8 {
            6
        } else {
            4
        }
    }
    #[zbus(property)]
    fn available_cursor_modes(&self) -> u32 {
        if self.0.mode.load(Ordering::SeqCst) == 7 {
            1
        } else {
            3
        }
    }
    async fn create_session(
        &self,
        options: Dict,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        self.0.event(Event::ScreenCreate)?;
        create_session(&self.0, options, header, conn).await
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
        let mut metadata = HashMap::from([
            ("size".to_owned(), value((1024i32, 768i32))),
            ("position".to_owned(), value((-1024i32, 0i32))),
            ("source_type".to_owned(), value(1u32)),
        ]);
        if self.0.mode.load(Ordering::SeqCst) == 8 {
            metadata.insert("pipewire-serial".into(), value(u64::from(u32::MAX) + 42));
        }
        let results = HashMap::from([("streams".into(), value(vec![(42u32, metadata)]))]);
        response(conn, &header, options, 0, results).await
    }
    async fn select_sources(
        &self,
        _session: OwnedObjectPath,
        options: Dict,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        let cursor = u32::try_from(
            options
                .get("cursor_mode")
                .ok_or_else(|| zbus::fdo::Error::InvalidArgs("cursor mode missing".into()))?,
        )
        .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        let persist = options
            .get("persist_mode")
            .map(u32::try_from)
            .transpose()
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        if options.contains_key("restore_token") {
            return Err(zbus::fdo::Error::InvalidArgs(
                "fresh consent required".into(),
            ));
        }
        self.0.event(Event::Sources(cursor, persist))?;
        response(conn, &header, options, 0, Dict::new()).await
    }
    fn open_pipe_wire_remote(
        &self,
        _session: OwnedObjectPath,
        _options: Dict,
    ) -> zbus::fdo::Result<zbus::zvariant::OwnedFd> {
        let (a, _b) = std::os::unix::net::UnixStream::pair()
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(OwnedFd::from(a).into())
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
struct LoginSession(Arc<State>, u32);
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
            self.1,
            OwnedObjectPath::try_from("/org/freedesktop/login1/user/test")
                .unwrap_or_else(|e| panic!("fixture path: {e}")),
        )
    }
}
struct Fixture {
    bus: Bus,
    server: Connection,
    state: Arc<State>,
    uid: u32,
    shutdown: watch::Sender<bool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let bus = Bus::new()?;
        // SAFETY: scalar current UID; fixture services deliberately run as this
        // user on their private bus, and never replace the actual system bus.
        let uid = unsafe { libc::geteuid() };
        let state = Arc::new(State::default());
        // Like actual OS services, the fixture has a runtime independent of the
        // application lease supervisor and its synchronous input calls.
        let (shutdown, mut stopped) = watch::channel(false);
        let (ready, result) = oneshot::channel();
        let address = bus.address.clone();
        let service_state = state.clone();
        let worker = thread::spawn(move || {
            let run = (|| -> io::Result<()> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(async {
                    let server = Builder::address(address.as_str())
                        .map_err(error)?
                        .name(PORTAL)
                        .map_err(error)?
                        .name(LOGIN)
                        .map_err(error)?
                        .serve_at(ROOT, Remote(service_state.clone()))
                        .map_err(error)?
                        .serve_at(ROOT, Screen(service_state.clone()))
                        .map_err(error)?
                        .serve_at(ROOT, ClipboardExtension(service_state.clone()))
                        .map_err(error)?
                        .serve_at("/org/freedesktop/login1", LoginManager)
                        .map_err(error)?
                        .serve_at(LOGIN_PATH, LoginSession(service_state, uid))
                        .map_err(error)?
                        .build()
                        .await
                        .map_err(error)?;
                    let _ = ready.send(server.clone());
                    let _ = stopped.changed().await;
                    let _ = tokio::time::timeout(Duration::from_millis(100), server.close()).await;
                    Ok(())
                })
            })();
            assert!(run.is_ok(), "fixture service failed: {run:?}");
        });
        let server = tokio::time::timeout(Duration::from_secs(2), result).await??;
        Ok(Self {
            bus,
            server,
            state,
            uid,
            shutdown,
            worker: Some(worker),
        })
    }
    async fn input(&self) -> Result<PortalInput> {
        let (_cancel, cancelled) = watch::channel(false);
        let mut cancelled = cancelled;
        Ok(PortalInput::request_at(
            PortalOptions::current_process(String::new()),
            Addresses {
                user: self.bus.address.clone(),
                system: self.bus.address.clone(),
                user_uid: self.uid,
                system_uid: self.uid,
            },
            &mut cancelled,
        )
        .await?)
    }
    async fn input_with_clipboard(&self) -> Result<PortalInput> {
        let (_cancel, mut cancelled) = watch::channel(false);
        Ok(PortalInput::request_for(
            PortalOptions::current_process(String::new()),
            Addresses {
                user: self.bus.address.clone(),
                system: self.bus.address.clone(),
                user_uid: self.uid,
                system_uid: self.uid,
            },
            &mut cancelled,
            RequestedAccess {
                purpose: Purpose::Control,
                clipboard: true,
                multiple_sources: true,
            },
        )
        .await?)
    }
    fn events(&self) -> Result<Vec<Event>> {
        Ok(self
            .state
            .events
            .lock()
            .map_err(|_| "fixture poisoned")?
            .clone())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn apply(input: &InputController<PortalInput>, sequence: u64, action: InputAction) -> Result {
    assert!(input.apply(&InputEvent {
        epoch: InputEpoch {
            input: 1,
            layout: 1,
            connection: 9
        },
        sequence,
        action
    })?);
    Ok(())
}

struct ClipboardLease(ClipboardBinding);
impl ClipboardAuthority for ClipboardLease {
    fn check(&self, binding: &ClipboardBinding, _: ClipboardDirection) -> io::Result<()> {
        if binding != &self.0 {
            return Err(denied("fixture clipboard lease binding mismatch"));
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clipboard_extension_uses_original_caller_start_grant_and_cleanup() -> Result {
    for system_lock in [false, true] {
        let fixture = Fixture::new().await?;
        let mut input = fixture.input_with_clipboard().await?;
        let original = input.control();
        let grant = input.take_clipboard_grant()?;
        assert!(input.take_clipboard_grant().is_err());
        let events = fixture.events()?;
        let position = |event| events.iter().position(|candidate| *candidate == event);
        let created = position(Event::RemoteCreate).ok_or("original CreateSession missing")?;
        let requested = position(Event::ClipboardRequest).ok_or("RequestClipboard missing")?;
        let started = position(Event::RemoteStart).ok_or("original Start missing")?;
        assert!(created < requested && requested < started);
        assert!(!events.contains(&Event::ScreenCreate));
        assert!(!events.contains(&Event::ClipboardRead));
        let binding = ClipboardBinding {
            session_id: "9113c8d8-46d3-47e4-b27c-95bacfddffca".into(),
            connection_generation: 9,
        };
        let (approval, _local_owner) =
            LocalClipboardApproval::approve_from_local_user(binding.clone(), true, false)?;
        let mut clipboard = PortalClipboard::open(
            grant,
            binding.clone(),
            approval,
            Arc::new(ClipboardLease(binding)),
        )?;
        clipboard.check()?;
        assert!(!fixture.events()?.contains(&Event::ClipboardRead));
        assert_eq!(
            clipboard.read_text()?.as_deref(),
            Some("original caller fixture 中文🙂")
        );
        if system_lock {
            fixture.state.locked.store(true, Ordering::SeqCst);
            fixture
                .server
                .emit_signal(
                    None::<&str>,
                    LOGIN_PATH,
                    "org.freedesktop.DBus.Properties",
                    "PropertiesChanged",
                    &(
                        LOGIN_SESSION,
                        HashMap::from([("LockedHint", value(true))]),
                        Vec::<String>::new(),
                    ),
                )
                .await?;
            clipboard
                .monitor()
                .wait_cleanup_until(Instant::now() + Duration::from_secs(2))?;
            assert!(clipboard.read_text().is_err());
        }
        clipboard.close()?;
        assert!(!original.is_active());
        assert!(input.check().is_err());
        assert_eq!(
            fixture
                .events()?
                .iter()
                .filter(|event| **event == Event::Close)
                .count(),
            1
        );
        input.begin_reset()?;
        input.reset()?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clipboard_extension_requires_real_boolean_start_and_available_interface() -> Result {
    for mode in [9, 10, 11] {
        let fixture = Fixture::new().await?;
        fixture.state.mode.store(mode, Ordering::SeqCst);
        assert!(fixture.input_with_clipboard().await.is_err());
        assert!(fixture.events()?.contains(&Event::ClipboardRequest));
        assert!(!fixture.events()?.contains(&Event::ClipboardRead));
    }
    let fixture = Fixture::new().await?;
    fixture
        .server
        .object_server()
        .remove::<ClipboardExtension, _>(ROOT)
        .await?;
    assert!(fixture.input_with_clipboard().await.is_err());
    assert!(!fixture.events()?.contains(&Event::ClipboardRead));
    let mut ordinary = fixture.input().await?;
    assert!(ordinary.take_clipboard_grant().is_err());
    ordinary.begin_reset()?;
    ordinary.reset()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_private_bus_consent_input_lock_and_owned_cleanup() -> Result {
    let fixture = Fixture::new().await?;
    let mut device = fixture.input().await?;
    assert!(device.take_clipboard_grant().is_err());
    assert!(!fixture.events()?.contains(&Event::ClipboardRequest));
    assert_eq!(device.layout().left, -1024);
    assert_eq!(device.info().streams[0].node_id, 42);
    let _pipewire = device.take_pipewire_fd()?;
    assert!(device.take_pipewire_fd().is_err());
    let (mut runtime, input, _stop, _peer) = crate::x11::tests::create_runtime(device)?;
    apply(&input, 1, InputAction::Text("中😀\n".into()))?;
    apply(
        &input,
        2,
        InputAction::Key {
            code: 0xe4,
            down: true,
        },
    )?;
    apply(
        &input,
        3,
        InputAction::Pointer {
            button: Some(1),
            down: true,
            x: -800,
            y: 125,
        },
    )?;
    let events = fixture.events()?;
    assert!(events.contains(&Event::Devices(3, 0)));
    assert!(events.contains(&Event::Symbol(0x01004e2d, 1)));
    assert!(events.contains(&Event::Symbol(0x0101f600, 0)));
    assert!(events.contains(&Event::Key(97, 1)));
    assert!(events.contains(&Event::Motion(42, 224.0, 125.0)));
    assert!(events.contains(&Event::Button(0x110, 1)));
    fixture.state.locked.store(true, Ordering::SeqCst);
    fixture
        .server
        .emit_signal(
            None::<&str>,
            LOGIN_PATH,
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &(
                LOGIN_SESSION,
                HashMap::from([("LockedHint", value(true))]),
                Vec::<String>::new(),
            ),
        )
        .await?;
    // No new remote event is needed to observe OS lock and stop the lease.
    let report = tokio::time::timeout(Duration::from_secs(2), runtime.wait_stopped()).await??;
    assert_eq!(report.reason, StopReason::PlatformChanged);
    assert_eq!(report.cleanup, CleanupStatus::Succeeded);
    let events = fixture.events()?;
    assert!(events.contains(&Event::Key(97, 0)));
    assert!(events.contains(&Event::Button(0x110, 0)));
    assert_eq!(events.iter().filter(|e| **e == Event::Close).count(), 1);
    assert!(
        input
            .apply(&InputEvent {
                epoch: InputEpoch {
                    input: 1,
                    layout: 1,
                    connection: 9
                },
                sequence: 4,
                action: InputAction::Text("禁止".into())
            })
            .is_err()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consent_denial_early_closed_and_owner_replacement_never_reopen_authority() -> Result {
    for mode in [1, 2, 5] {
        let fixture = Fixture::new().await?;
        fixture.state.mode.store(mode, Ordering::SeqCst);
        assert!(fixture.input().await.is_err());
    }
    let fixture = Fixture::new().await?;
    let mut device = fixture.input().await?;
    device.inject(PlatformInput::Action(&InputAction::Key {
        code: 4,
        down: true,
    }))?;
    fixture.server.release_name(PORTAL).await?;
    let replacement = Builder::address(fixture.bus.address.as_str())?
        .name(PORTAL)?
        .build()
        .await?;
    let started = Instant::now();
    while device.check().is_ok() && started.elapsed() < Duration::from_secs(2) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(device.check().is_err());
    assert!(
        device
            .inject(PlatformInput::Action(&InputAction::Key {
                code: 4,
                down: true
            }))
            .is_err()
    );
    device.begin_reset()?;
    device.reset()?;
    assert!(fixture.events()?.contains(&Event::Key(30, 0)));
    assert!(fixture.events()?.contains(&Event::Close));
    replacement.close().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_rpc_is_terminal_and_text_or_unowned_release_cannot_bypass_it() -> Result {
    let fixture = Fixture::new().await?;
    let mut device = fixture.input().await?;
    device.inject(PlatformInput::Action(&InputAction::Key {
        code: 4,
        down: false,
    }))?;
    assert!(!fixture.events()?.contains(&Event::Key(30, 0)));
    fixture.state.mode.store(3, Ordering::SeqCst);
    let started = Instant::now();
    assert!(
        device
            .inject(PlatformInput::Action(&InputAction::Key {
                code: 4,
                down: true
            }))
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    device.begin_reset()?;
    let _ = device.reset();
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert!(
        device
            .inject(PlatformInput::Action(&InputAction::Text("禁止".into())))
            .is_err()
    );
    assert!(!fixture.events()?.contains(&Event::Key(30, 1)));
    assert!(fixture.events()?.contains(&Event::Close));
    Ok(())
}

#[test]
fn external_bus_and_wrong_parent_are_rejected_before_connecting() -> Result {
    for address in [
        "tcp:host=127.0.0.1,port=1",
        "unix:path=/tmp/bus;tcp:host=127.0.0.1,port=1",
        "autolaunch:",
    ] {
        assert!(valid_address(address).is_err());
    }
    assert!(
        PortalOptions::current_process("x11:0x123".into())
            .validate()
            .is_err()
    );
    Ok(())
}

#[test]
fn logical_metadata_preserves_mirrored_monitors_and_rejects_duplicate_nodes() -> Result {
    let monitor = || {
        HashMap::from([
            ("size".to_owned(), value((1920i32, 1080i32))),
            ("position".to_owned(), value((0i32, 0i32))),
            ("source_type".to_owned(), value(1u32)),
        ])
    };
    let info = parse_streams(
        HashMap::from([
            ("devices".to_owned(), value(3u32)),
            (
                "streams".to_owned(),
                value(vec![(43u32, monitor()), (42u32, monitor())]),
            ),
        ]),
        Purpose::Control,
    )?;
    assert_eq!(info.streams.len(), 2);
    assert_eq!(info.streams[0].node_id, 42);
    assert_eq!(info.layout.width, 1920);
    assert!(
        parse_streams(
            HashMap::from([
                ("devices".to_owned(), value(3u32)),
                (
                    "streams".to_owned(),
                    value(vec![(42u32, monitor()), (42u32, monitor())])
                )
            ]),
            Purpose::Control
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn stable_pipewire_serial_is_preserved_and_malformed_or_duplicate_serials_are_rejected() -> Result {
    let monitor = |serial: Option<OwnedValue>| {
        let mut properties = HashMap::from([
            ("size".to_owned(), value((1920i32, 1080i32))),
            ("position".to_owned(), value((0i32, 0i32))),
            ("source_type".to_owned(), value(1u32)),
        ]);
        if let Some(serial) = serial {
            properties.insert("pipewire-serial".into(), serial);
        }
        properties
    };
    let parse = |streams| {
        parse_streams(
            HashMap::from([("streams".into(), value(streams))]),
            Purpose::View,
        )
    };
    let serial = u64::from(u32::MAX) + 42;
    let info = parse(vec![
        (42u32, monitor(Some(value(serial)))),
        (43, monitor(None)),
    ])?;
    assert_eq!(info.streams[0].pipewire_serial, Some(serial));
    assert_eq!(info.streams[1].pipewire_serial, None);
    assert!(parse(vec![(42u32, monitor(Some(value(0u64))))]).is_err());
    assert!(parse(vec![(42u32, monitor(Some(value(42u32))))]).is_err());
    assert!(parse(vec![(42u32, monitor(Some(value("42"))))]).is_err());
    assert!(
        parse(vec![
            (42u32, monitor(Some(value(serial)))),
            (43, monitor(Some(value(serial))))
        ])
        .is_err()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_dialog_closes_the_original_bus_client_without_using_its_grant() -> Result {
    let fixture = Fixture::new().await?;
    fixture.state.mode.store(4, Ordering::SeqCst);
    let (cancel, mut cancelled) = watch::channel(false);
    let addresses = Addresses {
        user: fixture.bus.address.clone(),
        system: fixture.bus.address.clone(),
        user_uid: fixture.uid,
        system_uid: fixture.uid,
    };
    let task = tokio::spawn(async move {
        PortalInput::request_at(
            PortalOptions::current_process(String::new()),
            addresses,
            &mut cancelled,
        )
        .await
    });
    let started = Instant::now();
    while !fixture.state.waiting.load(Ordering::SeqCst)
        && started.elapsed() < Duration::from_secs(2)
    {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(fixture.state.waiting.load(Ordering::SeqCst));
    cancel.send_replace(false);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !task.is_finished(),
        "a false cancellation update must not cancel consent"
    );
    drop(cancel);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await??
            .is_err()
    );
    let caller = fixture
        .state
        .caller
        .lock()
        .map_err(|_| "fixture poisoned")?
        .clone();
    let dbus = proxy(
        &fixture.server,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await?;
    let started = Instant::now();
    loop {
        let owner: std::result::Result<String, _> =
            dbus.call("GetNameOwner", &(caller.as_str(),)).await;
        if owner.is_err() {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "cancelled portal bus client remained live"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(fixture.events()?.iter().all(|event| !matches!(
        event,
        Event::Key(_, _) | Event::Symbol(_, _) | Event::Button(_, _) | Event::Motion(_, _, _)
    )));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn view_only_consent_uses_no_remote_interface_and_never_gains_input_authority() -> Result {
    for mode in [0, 6, 8] {
        let fixture = Fixture::new().await?;
        // This service deliberately has no RemoteDesktop interface. A view
        // request cannot silently query or request keyboard/pointer authority.
        fixture
            .server
            .object_server()
            .remove::<Remote, _>(ROOT)
            .await?;
        fixture.state.mode.store(mode, Ordering::SeqCst);
        let (_cancel, mut cancelled) = watch::channel(false);
        let mut view = PortalView::request_at(
            PortalOptions::current_process(String::new()),
            Addresses {
                user: fixture.bus.address.clone(),
                system: fixture.bus.address.clone(),
                user_uid: fixture.uid,
                system_uid: fixture.uid,
            },
            &mut cancelled,
        )
        .await?;
        assert_eq!(view.info().streams[0].node_id, 42);
        assert_eq!(
            view.info().streams[0].pipewire_serial,
            (mode == 8).then_some(u64::from(u32::MAX) + 42)
        );
        assert_eq!(view.info().layout.left, -1024);
        let fd = view.take_pipewire_fd()?;
        assert!(view.take_pipewire_fd().is_err());
        assert!(!view.0.capabilities().physical_keys);
        assert!(
            view.0
                .inject(PlatformInput::Action(&InputAction::Text(
                    "forbidden".into()
                )))
                .is_err()
        );
        view.check()?;
        let events = fixture.events()?;
        assert!(events.contains(&Event::ScreenCreate));
        assert!(events.contains(&Event::ScreenStart));
        assert!(events.contains(&Event::Sources(2, if mode == 6 { None } else { Some(0) })));
        assert!(!events.iter().any(|e| matches!(
            e,
            Event::RemoteCreate
                | Event::ClipboardRequest
                | Event::ClipboardRead
                | Event::Devices(_, _)
                | Event::Key(_, _)
                | Event::Symbol(_, _)
        )));
        view.control().invalidate();
        assert!(view.check().is_err());
        view.close()?;
        assert_eq!(
            fixture
                .events()?
                .iter()
                .filter(|e| **e == Event::Close)
                .count(),
            1
        );
        drop(fd);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn view_only_lock_or_service_replacement_is_terminal_and_cursor_support_is_required() -> Result
{
    for replacement in [false, true] {
        let fixture = Fixture::new().await?;
        let (_cancel, mut cancelled) = watch::channel(false);
        let mut view = PortalView::request_at(
            PortalOptions::current_process(String::new()),
            Addresses {
                user: fixture.bus.address.clone(),
                system: fixture.bus.address.clone(),
                user_uid: fixture.uid,
                system_uid: fixture.uid,
            },
            &mut cancelled,
        )
        .await?;
        if replacement {
            fixture.server.release_name(PORTAL).await?;
        } else {
            fixture.state.locked.store(true, Ordering::SeqCst);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while view.check().is_ok() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(view.check().is_err());
        fixture.state.locked.store(false, Ordering::SeqCst);
        assert!(view.take_pipewire_fd().is_err());
        view.close()?;
        assert!(fixture.events()?.contains(&Event::Close));
    }
    let fixture = Fixture::new().await?;
    fixture.state.mode.store(7, Ordering::SeqCst);
    assert!(fixture.input().await.is_err());
    assert!(!fixture.events()?.contains(&Event::RemoteCreate));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_granted_screens_switch_without_closing_or_reacquiring_portal() -> Result {
    let fixture = Fixture::new().await?;
    fixture.state.mode.store(12, Ordering::SeqCst);
    let mut device = fixture.input().await?;
    let granted = device.info().clone();
    assert_eq!(
        granted
            .streams
            .iter()
            .map(|s| s.node_id)
            .collect::<Vec<_>>(),
        vec![42, 77]
    );
    let bounds = granted.streams[0].layout;
    assert_eq!(bounds, granted.streams[1].layout);
    device.select_source(42, bounds)?;
    let (mut runtime, input, _stop, _peer) = crate::x11::tests::create_runtime(device)?;
    apply(
        &input,
        1,
        InputAction::Key {
            code: 4,
            down: true,
        },
    )?;
    apply(
        &input,
        2,
        InputAction::Pointer {
            button: Some(1),
            down: true,
            x: -800,
            y: 125,
        },
    )?;
    let replacement = input.select_source(77, bounds)?;
    assert_eq!(
        replacement,
        InputEpoch {
            input: 2,
            layout: 2,
            connection: 9
        }
    );
    assert!(input.apply(&InputEvent {
        epoch: replacement,
        sequence: 1,
        action: InputAction::Pointer {
            button: None,
            down: false,
            x: -800,
            y: 125,
        }
    })?);
    assert!(!input.apply(&InputEvent {
        epoch: InputEpoch {
            input: 1,
            layout: 1,
            connection: 9
        },
        sequence: 3,
        action: InputAction::Pointer {
            button: None,
            down: false,
            x: -800,
            y: 125
        }
    })?);
    {
        let events = fixture.events()?;
        let target = events
            .iter()
            .position(|event| *event == Event::Motion(77, 224.0, 125.0))
            .ok_or("selected node not used")?;
        for release in [Event::Key(30, 0), Event::Button(0x110, 0)] {
            assert!(
                events
                    .iter()
                    .position(|event| *event == release)
                    .ok_or("held input not released")?
                    < target
            );
        }
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == Event::RemoteCreate)
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == Event::RemoteStart)
                .count(),
            1
        );
        assert!(!events.contains(&Event::Close));
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == Event::Motion(42, 224.0, 125.0))
                .count(),
            1
        );
    }
    runtime.shutdown(StopReason::ExplicitExit).await?;
    let events = fixture.events()?;
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == Event::Close)
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == Event::RemoteCreate)
            .count(),
        1
    );
    Ok(())
}
