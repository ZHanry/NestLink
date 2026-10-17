//! The authenticated local GUI's original logind session constrains platform IO.
//! All system-bus work runs on a dedicated runtime; caller runtimes are never
//! re-entered. Losing facts or the original logind owner is terminal.
#![allow(unsafe_code)]

use futures_util::StreamExt;
use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc as async_mpsc, watch};
use zbus::{
    Connection, Proxy,
    connection::Builder,
    zvariant::{OwnedObjectPath, OwnedValue},
};

const LOGIN: &str = "org.freedesktop.login1";
const INTERFACE: &str = "org.freedesktop.login1.Session";
const IPC: Duration = Duration::from_millis(150);
const HEARTBEAT: Duration = Duration::from_millis(500);
#[derive(Clone, Copy)]
enum Desktop {
    X11(u16),
    Wayland,
}
fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
type Dict = HashMap<String, OwnedValue>;
struct Check {
    until: Instant,
    reply: mpsc::SyncSender<io::Result<()>>,
}
pub struct LinuxDesktopSession {
    active: Arc<AtomicBool>,
    heartbeat: Arc<Mutex<Instant>>,
    checks: async_mpsc::Sender<Check>,
    stop: watch::Sender<bool>,
    worker: Option<thread::JoinHandle<()>>,
}
/// Read-only fact observation; this handle cannot set or renew OS authority.
#[derive(Clone)]
pub struct LinuxSessionState(Arc<AtomicBool>, Arc<Mutex<Instant>>);
impl LinuxSessionState {
    pub fn is_active(&self) -> bool {
        let healthy = self.0.load(Ordering::SeqCst)
            && self.1.lock().is_ok_and(|time| time.elapsed() <= HEARTBEAT);
        if !healthy {
            self.0.store(false, Ordering::SeqCst);
        }
        healthy
    }
}
impl LinuxDesktopSession {
    pub fn state(&self) -> LinuxSessionState {
        LinuxSessionState(self.active.clone(), self.heartbeat.clone())
    }
    pub fn is_active(&self) -> bool {
        self.state().is_active()
    }
    /// `desktop_pid` must come from the local GUI or its authenticated IPC
    /// peer, never a network caller. The display must be its local X11 server.
    pub fn open(desktop_pid: u32, display: &str) -> io::Result<Self> {
        Self::open_desktop(desktop_pid, Desktop::X11(display_number(display)?))
    }
    /// Read the actual Wayland login of the local GUI. This opens no portal,
    /// screen, input, microphone or audio stream.
    pub fn open_wayland(desktop_pid: u32) -> io::Result<Self> {
        Self::open_desktop(desktop_pid, Desktop::Wayland)
    }
    fn open_desktop(pid: u32, desktop: Desktop) -> io::Result<Self> {
        // SAFETY: scalar effective-user query, no memory or ownership involved.
        let uid = unsafe { libc::geteuid() };
        Self::open_at(
            "unix:path=/run/dbus/system_bus_socket",
            0,
            uid,
            pid,
            desktop,
        )
    }
    fn open_at(
        address: &str,
        bus_uid: u32,
        uid: u32,
        pid: u32,
        desktop: Desktop,
    ) -> io::Result<Self> {
        if pid == 0
            || address.len() > 4096
            || address.contains(';')
            || !address.starts_with("unix:path=/")
        {
            return Err(denied(
                "platform IO requires a local desktop PID and one Unix system bus",
            ));
        }
        let address = address.to_owned();
        let active = Arc::new(AtomicBool::new(false));
        let state = Arc::clone(&active);
        let heartbeat = Arc::new(Mutex::new(Instant::now()));
        let worker_heartbeat = heartbeat.clone();
        let (checks, receive) = async_mpsc::channel(1);
        let (stop, stopping) = watch::channel(false);
        let (ready, result) = mpsc::sync_channel(1);
        let deadline = Instant::now() + Duration::from_secs(2);
        let worker = thread::Builder::new()
            .name("nestlink-desktop-login".into())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    runtime.block_on(run(
                        &address,
                        bus_uid,
                        uid,
                        pid,
                        desktop,
                        deadline,
                        &state,
                        &worker_heartbeat,
                        receive,
                        stopping,
                        ready,
                    ))
                }));
                state.store(false, Ordering::SeqCst);
                // The worker has no input authority or held OS resources to release.
                // A panic, failed startup, and transport loss have the same terminal result.
                let _ = outcome;
            })?;
        match result.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Ok(())) => Ok(Self {
                active,
                heartbeat,
                checks,
                stop,
                worker: Some(worker),
            }),
            result => {
                stop.send_replace(true);
                if worker.is_finished() {
                    let _ = worker.join();
                }
                match result {
                    Ok(Err(error)) => Err(error),
                    _ => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "local desktop login startup failed or timed out",
                    )),
                }
            }
        }
    }
    #[cfg(test)]
    fn check(&self) -> io::Result<()> {
        self.check_until(Instant::now() + IPC)
    }
    pub fn check_until(&self, until: Instant) -> io::Result<()> {
        if !self.is_active() {
            return Err(denied("local desktop login monitor is terminal"));
        }
        if Instant::now() >= until {
            self.active.store(false, Ordering::SeqCst);
            self.stop.send_replace(true);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local desktop login check budget already exhausted",
            ));
        }
        let (reply, result) = mpsc::sync_channel(1);
        let result = self
            .checks
            .try_send(Check { until, reply })
            .map_err(|_| denied("local desktop login monitor unavailable"))
            .and_then(|()| {
                result
                    .recv_timeout(until.saturating_duration_since(Instant::now()))
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "local desktop login check timed out",
                        )
                    })?
            });
        if result.is_err() {
            self.active.store(false, Ordering::SeqCst);
            self.stop.send_replace(true);
        }
        result
    }
}
impl Drop for LinuxDesktopSession {
    fn drop(&mut self) {
        self.active.store(false, Ordering::SeqCst);
        self.stop.send_replace(true);
        if let Some(worker) = self.worker.take()
            && worker.is_finished()
        {
            let _ = worker.join();
        }
    }
}
fn error(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::other(e)
}
fn display_number(display: &str) -> io::Result<u16> {
    let parsed = x11rb_protocol::parse_display::parse_display(Some(display)).map_err(error)?;
    if display.len() > 32
        || !display.starts_with(':')
        || !parsed.host.is_empty()
        || parsed.protocol.is_some()
    {
        return Err(denied(
            "logind display must identify a local Unix X11 server",
        ));
    }
    Ok(parsed.display)
}
async fn bounded<T>(
    until: Instant,
    future: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    if Instant::now() >= until {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "X11 login budget exhausted before dispatch",
        ));
    }
    tokio::time::timeout_at(tokio::time::Instant::from_std(until), future)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "X11 login budget exhausted"))?
}
async fn proxy(
    conn: &Connection,
    owner: &str,
    path: &str,
    interface: &str,
) -> io::Result<Proxy<'static>> {
    Proxy::new(
        conn,
        owner.to_owned(),
        path.to_owned(),
        interface.to_owned(),
    )
    .await
    .map_err(error)
}
async fn owner(conn: &Connection, uid: u32) -> io::Result<String> {
    let bus = proxy(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await?;
    let owner: String = bus.call("GetNameOwner", &(LOGIN,)).await.map_err(error)?;
    let user: u32 = bus
        .call("GetConnectionUnixUser", &(owner.as_str(),))
        .await
        .map_err(error)?;
    if user != uid || !owner.starts_with(':') {
        return Err(denied("logind owner identity changed"));
    }
    Ok(owner)
}
fn validate(facts: &Dict, uid: u32, desktop: Desktop) -> io::Result<()> {
    if facts.len() > 64 {
        return Err(denied("logind properties exceed budget"));
    }
    let fact = |name| {
        facts
            .get(name)
            .ok_or_else(|| denied("required logind fact missing"))
    };
    let active = bool::try_from(fact("Active")?).map_err(error)?;
    let locked = bool::try_from(fact("LockedHint")?).map_err(error)?;
    let kind = <&str>::try_from(fact("Type")?).map_err(error)?;
    let class = <&str>::try_from(fact("Class")?).map_err(error)?;
    let actual_display = <&str>::try_from(fact("Display")?).map_err(error)?;
    let user: (u32, OwnedObjectPath) = fact("User")?
        .try_clone()
        .map_err(error)?
        .try_into()
        .map_err(error)?;
    if !active
        || locked
        || !match desktop {
            Desktop::X11(display) => kind == "x11" && display_number(actual_display)? == display,
            Desktop::Wayland => kind == "wayland" && actual_display.len() <= 32,
        }
        || !matches!(class, "user" | "user-early")
        || user.0 != uid
    {
        return Err(denied(
            "login is locked, inactive, or belongs to another desktop",
        ));
    }
    Ok(())
}
async fn facts(
    conn: &Connection,
    pinned: &str,
    path: &str,
    bus_uid: u32,
    uid: u32,
    desktop: Desktop,
) -> io::Result<()> {
    if owner(conn, bus_uid).await? != pinned {
        return Err(denied("original logind service disappeared"));
    }
    let reply = proxy(conn, pinned, path, "org.freedesktop.DBus.Properties")
        .await?
        .call_method("GetAll", &(INTERFACE,))
        .await
        .map_err(error)?;
    if reply.body().len() > 32 * 1024 {
        return Err(denied("logind reply exceeds message budget"));
    }
    validate(&reply.body().deserialize().map_err(error)?, uid, desktop)
}
fn session_changed(message: &zbus::Message) -> io::Result<bool> {
    if message.body().len() > 32 * 1024 {
        return Err(denied("logind signal exceeds message budget"));
    }
    let (interface, changed, invalidated): (String, Dict, Vec<String>) =
        message.body().deserialize().map_err(error)?;
    if changed.len() > 64 || invalidated.len() > 64 {
        return Err(denied("logind signal property budget exceeded"));
    }
    let relevant = |name: &str| {
        matches!(
            name,
            "Active" | "LockedHint" | "Type" | "Class" | "Display" | "User"
        )
    };
    Ok(interface == INTERFACE
        && (changed.keys().any(|name| relevant(name))
            || invalidated.iter().any(|name| relevant(name))))
}
fn owner_changed(message: &zbus::Message) -> io::Result<bool> {
    if message.body().len() > 4096 {
        return Err(denied("logind owner signal exceeds message budget"));
    }
    let (name, _old, _new): (String, String, String) =
        message.body().deserialize().map_err(error)?;
    Ok(name == LOGIN)
}
#[allow(clippy::too_many_arguments)]
async fn run(
    address: &str,
    bus_uid: u32,
    uid: u32,
    pid: u32,
    desktop: Desktop,
    deadline: Instant,
    active: &AtomicBool,
    heartbeat: &Mutex<Instant>,
    mut checks: async_mpsc::Receiver<Check>,
    mut stop: watch::Receiver<bool>,
    ready: mpsc::SyncSender<io::Result<()>>,
) -> io::Result<()> {
    let startup = bounded(deadline, async {
        let conn = Builder::address(address)
            .map_err(error)?
            .auth_mechanism(zbus::AuthMechanism::External)
            .max_queued(8)
            .method_timeout(IPC)
            .build()
            .await
            .map_err(error)?;
        if conn.peer_creds().await?.unix_user_id() != Some(bus_uid) {
            let _ = conn.close().await;
            return Err(denied("system bus peer identity mismatch"));
        }
        let pinned = owner(&conn, bus_uid).await?;
        let manager = proxy(
            &conn,
            &pinned,
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await?;
        let path: OwnedObjectPath = manager
            .call("GetSessionByPID", &(pid,))
            .await
            .map_err(error)?;
        // Subscribe before observing initial facts: a quick lock/unlock or
        // owner departure/return must not disappear between snapshot polls.
        let changes = proxy(
            &conn,
            &pinned,
            path.as_str(),
            "org.freedesktop.DBus.Properties",
        )
        .await?
        .receive_signal_with_args("PropertiesChanged", &[(0, INTERFACE)])
        .await
        .map_err(error)?;
        let owners = proxy(
            &conn,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .await?
        .receive_signal_with_args("NameOwnerChanged", &[(0, LOGIN)])
        .await
        .map_err(error)?;
        facts(&conn, &pinned, path.as_str(), bus_uid, uid, desktop).await?;
        Ok((conn, pinned, path, changes, owners))
    })
    .await;
    let (conn, pinned, path, mut changes, mut owners) = match startup {
        Ok(value) => value,
        Err(error) => {
            let _ = ready.send(Err(error));
            return Ok(());
        }
    };
    if *stop.borrow() {
        return Ok(());
    }
    *heartbeat
        .lock()
        .map_err(|_| io::Error::other("login heartbeat poisoned"))? = Instant::now();
    active.store(true, Ordering::SeqCst);
    if ready.send(Ok(())).is_err() {
        active.store(false, Ordering::SeqCst);
        return Ok(());
    }
    let mut poll = tokio::time::interval(Duration::from_millis(250));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut irrelevant_signals = 0;
    loop {
        if !active.load(Ordering::SeqCst)
            || !heartbeat
                .lock()
                .is_ok_and(|time| time.elapsed() <= HEARTBEAT)
            || irrelevant_signals >= 128
        {
            break;
        }
        let request = tokio::select! {
            biased;
            _ = stop.changed() => break,
            signal = changes.next() => { match signal {
                Some(signal) if matches!(session_changed(&signal), Ok(false)) => { irrelevant_signals += 1; continue; },
                _ => break,
            } },
            signal = owners.next() => { match signal {
                Some(signal) if matches!(owner_changed(&signal), Ok(false)) => { irrelevant_signals += 1; continue; },
                _ => break,
            } },
            check = checks.recv() => match check { Some(check) => Some(check), None => break },
            _ = poll.tick() => None,
        };
        let until = request
            .as_ref()
            .map_or_else(|| Instant::now() + IPC, |check| check.until);
        let query = bounded(
            until,
            facts(&conn, &pinned, path.as_str(), bus_uid, uid, desktop),
        );
        tokio::pin!(query);
        let result = loop {
            if Instant::now() >= until || irrelevant_signals >= 128 {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "X11 login signal/check budget exhausted",
                ));
            }
            tokio::select! {
                biased;
                _ = stop.changed() => break Err(denied("X11 login monitor stopped")),
                signal = changes.next() => { match signal {
                    Some(signal) if matches!(session_changed(&signal), Ok(false)) => { irrelevant_signals += 1; continue; },
                    _ => break Err(denied("X11 login facts changed")),
                } },
                signal = owners.next() => { match signal {
                    Some(signal) if matches!(owner_changed(&signal), Ok(false)) => { irrelevant_signals += 1; continue; },
                    _ => break Err(denied("X11 logind owner changed")),
                } },
                result = &mut query => break result,
            }
        };
        let result = result.and_then(|()| {
            let mut time = heartbeat
                .lock()
                .map_err(|_| io::Error::other("login heartbeat poisoned"))?;
            if !active.load(Ordering::SeqCst) || time.elapsed() > HEARTBEAT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original login monitor stalled",
                ));
            }
            *time = Instant::now();
            Ok(())
        });
        irrelevant_signals = 0;
        let failed = result.is_err();
        if failed {
            active.store(false, Ordering::SeqCst);
        }
        if let Some(check) = request {
            let _ = check.reply.send(result);
        }
        if failed {
            break;
        }
    }
    active.store(false, Ordering::SeqCst);
    let _ = bounded(Instant::now() + IPC, async {
        conn.close().await.map_err(error)
    })
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        os::fd::AsRawFd,
        process::{Child, Command, Stdio},
    };
    use zbus::interface;
    use zbus::zvariant::Value;
    fn valid() -> Dict {
        let value = |v| OwnedValue::try_from(v).unwrap_or_else(|e| panic!("fixture: {e}"));
        HashMap::from([
            ("Active".into(), value(Value::from(true))),
            ("LockedHint".into(), value(Value::from(false))),
            ("Type".into(), value(Value::from("x11"))),
            ("Class".into(), value(Value::from("user"))),
            ("Display".into(), value(Value::from(":47.0"))),
            (
                "User".into(),
                value(Value::from((
                    1000u32,
                    OwnedObjectPath::try_from("/user/1000")
                        .unwrap_or_else(|e| panic!("fixture: {e}")),
                ))),
            ),
        ])
    }
    #[test]
    fn login_binding_rejects_lock_greeter_wrong_user_or_display() {
        assert!(validate(&valid(), 1000, Desktop::X11(47)).is_ok());
        assert!(validate(&valid(), 1001, Desktop::X11(47)).is_err());
        assert!(validate(&valid(), 1000, Desktop::X11(48)).is_err());
        for (key, value) in [
            ("LockedHint", Value::from(true)),
            ("Active", Value::from(false)),
            ("Class", Value::from("greeter")),
            ("Type", Value::from("wayland")),
            ("Display", Value::from("localhost:47")),
        ] {
            let mut facts = valid();
            facts.insert(
                key.into(),
                OwnedValue::try_from(value).unwrap_or_else(|e| panic!("fixture: {e}")),
            );
            assert!(validate(&facts, 1000, Desktop::X11(47)).is_err(), "{key}");
        }
        for key in ["LockedHint", "Active", "Class", "Type", "Display", "User"] {
            let mut facts = valid();
            facts.remove(key);
            assert!(validate(&facts, 1000, Desktop::X11(47)).is_err(), "{key}");
        }
    }
    #[test]
    fn wayland_facts_require_the_original_user_and_graphical_session_type() {
        let mut facts = valid();
        facts.insert(
            "Type".into(),
            OwnedValue::try_from(Value::from("wayland")).unwrap_or_else(|e| panic!("fixture: {e}")),
        );
        facts.insert(
            "Display".into(),
            OwnedValue::try_from(Value::from("")).unwrap_or_else(|e| panic!("fixture: {e}")),
        );
        assert!(validate(&facts, 1000, Desktop::Wayland).is_ok());
        assert!(validate(&facts, 1001, Desktop::Wayland).is_err());
        assert!(validate(&facts, 1000, Desktop::X11(47)).is_err());
        facts.insert(
            "Type".into(),
            OwnedValue::try_from(Value::from("tty")).unwrap_or_else(|e| panic!("fixture: {e}")),
        );
        assert!(validate(&facts, 1000, Desktop::Wayland).is_err());
    }
    #[test]
    fn expired_monitor_heartbeat_is_sticky_even_if_worker_later_returns() -> io::Result<()> {
        let active = Arc::new(AtomicBool::new(true));
        let heartbeat = Arc::new(Mutex::new(Instant::now() - HEARTBEAT * 2));
        let state = LinuxSessionState(active, heartbeat.clone());
        assert!(!state.is_active());
        *heartbeat
            .lock()
            .map_err(|_| io::Error::other("fixture lock"))? = Instant::now();
        assert!(
            !state.is_active(),
            "a late worker cannot restore old session facts"
        );
        Ok(())
    }
    struct Bus {
        child: Child,
        _directory: tempfile::TempDir,
        address: String,
    }
    impl Bus {
        fn new() -> io::Result<Self> {
            let directory = tempfile::Builder::new()
                .prefix("nestlink-x11-login-")
                .tempdir()?;
            let address = format!("unix:path={}", directory.path().join("bus").display());
            let mut child = Command::new("dbus-daemon")
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
                    .ok_or_else(|| io::Error::other("readiness pipe absent"))?;
                // SAFETY: this owned child pipe stays open during the nonblocking read.
                if unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                    return Err(io::Error::last_os_error());
                }
                let until = Instant::now() + Duration::from_secs(2);
                let mut bytes = Vec::new();
                while !bytes.contains(&b'\n') {
                    if Instant::now() >= until || bytes.len() > 4096 {
                        return Err(io::Error::other("owned bus did not become ready"));
                    }
                    let mut buffer = [0; 256];
                    match stdout.read(&mut buffer) {
                        Ok(0) => return Err(io::Error::other("owned bus exited")),
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
    struct Manager;
    #[interface(name = "org.freedesktop.login1.Manager")]
    impl Manager {
        #[zbus(name = "GetSessionByPID")]
        fn get_session_by_pid(&self, pid: u32) -> zbus::fdo::Result<OwnedObjectPath> {
            if pid != std::process::id() {
                return Err(zbus::fdo::Error::InvalidArgs("wrong GUI PID".into()));
            }
            OwnedObjectPath::try_from("/org/freedesktop/login1/session/owned")
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
        }
    }
    struct Session {
        locked: Arc<AtomicBool>,
        uid: u32,
        kind: &'static str,
    }
    #[interface(name = "org.freedesktop.login1.Session")]
    impl Session {
        #[zbus(property)]
        fn active(&self) -> bool {
            true
        }
        #[zbus(property)]
        fn locked_hint(&self) -> bool {
            self.locked.load(Ordering::SeqCst)
        }
        #[zbus(property)]
        fn r#type(&self) -> &str {
            self.kind
        }
        #[zbus(property)]
        fn class(&self) -> &str {
            "user"
        }
        #[zbus(property)]
        fn display(&self) -> &str {
            ":47"
        }
        #[zbus(property)]
        fn user(&self) -> zbus::fdo::Result<(u32, OwnedObjectPath)> {
            Ok((
                self.uid,
                OwnedObjectPath::try_from("/user/owned")
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?,
            ))
        }
    }
    enum Control {
        Release(mpsc::SyncSender<io::Result<()>>),
        PulseLock(mpsc::SyncSender<io::Result<()>>),
        Stop,
    }
    struct Server {
        control: async_mpsc::UnboundedSender<Control>,
        thread: Option<thread::JoinHandle<()>>,
        locked: Arc<AtomicBool>,
    }
    impl Server {
        fn new(bus: &Bus, uid: u32) -> io::Result<Self> {
            Self::new_for(bus, uid, "x11")
        }
        fn new_for(bus: &Bus, uid: u32, kind: &'static str) -> io::Result<Self> {
            let address = bus.address.clone();
            let locked = Arc::new(AtomicBool::new(false));
            let session_lock = Arc::clone(&locked);
            let (control, mut receive) = async_mpsc::unbounded_channel();
            let (ready, result) = mpsc::sync_channel(1);
            let worker = thread::spawn(move || {
                let run = || -> io::Result<()> {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    runtime.block_on(async {
                        let conn = Builder::address(address.as_str())
                            .map_err(error)?
                            .auth_mechanism(zbus::AuthMechanism::External)
                            .name(LOGIN)
                            .map_err(error)?
                            .serve_at("/org/freedesktop/login1", Manager)
                            .map_err(error)?
                            .serve_at(
                                "/org/freedesktop/login1/session/owned",
                                Session {
                                    locked: session_lock,
                                    uid,
                                    kind,
                                },
                            )
                            .map_err(error)?
                            .build()
                            .await
                            .map_err(error)?;
                        let _ = ready.send(Ok(()));
                        while let Some(control) = receive.recv().await {
                            match control {
                                Control::Release(reply) => {
                                    let result =
                                        conn.release_name(LOGIN).await.map(|_| ()).map_err(error);
                                    let _ = reply.send(result);
                                }
                                Control::PulseLock(reply) => {
                                    let result = async {
                                        for locked in [true, false] {
                                            let properties = Dict::from([(
                                                "LockedHint".into(),
                                                OwnedValue::from(locked),
                                            )]);
                                            conn.emit_signal(
                                                None::<&str>,
                                                "/org/freedesktop/login1/session/owned",
                                                "org.freedesktop.DBus.Properties",
                                                "PropertiesChanged",
                                                &(INTERFACE, properties, Vec::<String>::new()),
                                            )
                                            .await
                                            .map_err(error)?;
                                        }
                                        Ok(())
                                    }
                                    .await;
                                    let _ = reply.send(result);
                                }
                                Control::Stop => break,
                            }
                        }
                        conn.close().await.map_err(error)
                    })
                };
                if let Err(error) = run() {
                    let _ = ready.send(Err(error));
                }
            });
            result
                .recv_timeout(Duration::from_secs(2))
                .map_err(error)??;
            Ok(Self {
                control,
                thread: Some(worker),
                locked,
            })
        }
        fn release(&self) -> io::Result<()> {
            let (reply, result) = mpsc::sync_channel(1);
            self.control.send(Control::Release(reply)).map_err(error)?;
            result.recv_timeout(Duration::from_secs(2)).map_err(error)?
        }
        fn pulse_lock(&self) -> io::Result<()> {
            let (reply, result) = mpsc::sync_channel(1);
            self.control
                .send(Control::PulseLock(reply))
                .map_err(error)?;
            result.recv_timeout(Duration::from_secs(2)).map_err(error)?
        }
    }
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.control.send(Control::Stop);
            if let Some(worker) = self.thread.take() {
                let _ = worker.join();
            }
        }
    }
    #[test]
    fn private_bus_lock_and_owner_replacement_end_the_original_login() -> io::Result<()> {
        let bus = Bus::new()?;
        // SAFETY: scalar effective UID, only used for this private fixture bus.
        let uid = unsafe { libc::geteuid() };
        let server = Server::new(&bus, uid)?;
        let login = LinuxDesktopSession::open_at(
            &bus.address,
            uid,
            uid,
            std::process::id(),
            Desktop::X11(47),
        )?;
        login.check()?;
        server.locked.store(true, Ordering::SeqCst);
        let until = Instant::now() + Duration::from_secs(1);
        while login.active.load(Ordering::SeqCst) && Instant::now() < until {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !login.active.load(Ordering::SeqCst),
            "idle monitor must observe lock"
        );
        assert!(login.check().is_err());
        server.locked.store(false, Ordering::SeqCst);
        assert!(
            login.check().is_err(),
            "unlock cannot restore old input authority"
        );
        let transient = LinuxDesktopSession::open_at(
            &bus.address,
            uid,
            uid,
            std::process::id(),
            Desktop::X11(47),
        )?;
        server.pulse_lock()?;
        assert!(
            transient.check().is_err(),
            "a lock/unlock between polls still ends authority"
        );
        let login = LinuxDesktopSession::open_at(
            &bus.address,
            uid,
            uid,
            std::process::id(),
            Desktop::X11(47),
        )?;
        server.release()?;
        let replacement = Server::new(&bus, uid)?;
        assert!(
            login.check().is_err(),
            "a new owner cannot inherit old input authority"
        );
        assert!(
            LinuxDesktopSession::open_at(
                &bus.address,
                uid,
                uid,
                std::process::id(),
                Desktop::X11(48)
            )
            .is_err()
        );
        assert!(
            LinuxDesktopSession::open_at(
                &bus.address,
                uid,
                uid.wrapping_add(1),
                std::process::id(),
                Desktop::X11(47)
            )
            .is_err()
        );
        assert!(!replacement.locked.load(Ordering::SeqCst));
        Ok(())
    }
    #[test]
    fn private_bus_wayland_lock_signal_ends_the_original_login() -> io::Result<()> {
        let bus = Bus::new()?;
        // SAFETY: scalar effective UID, used only for the private fixture.
        let uid = unsafe { libc::geteuid() };
        let server = Server::new_for(&bus, uid, "wayland")?;
        assert!(
            LinuxDesktopSession::open_at(
                &bus.address,
                uid,
                uid,
                std::process::id(),
                Desktop::X11(47)
            )
            .is_err()
        );
        let login = LinuxDesktopSession::open_at(
            &bus.address,
            uid,
            uid,
            std::process::id(),
            Desktop::Wayland,
        )?;
        login.check()?;
        server.pulse_lock()?;
        assert!(login.check().is_err());
        assert!(!login.state().is_active());
        Ok(())
    }
}
