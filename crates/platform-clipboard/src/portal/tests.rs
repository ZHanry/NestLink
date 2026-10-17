//! Actual private D-Bus RPC and owned-FD fixtures. These are not GNOME/KDE
//! desktop acceptance and never connect to the current user's desktop bus.
use super::*;
use crate::{
    NativeClipboard,
    tests::{authority, binding, context},
};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Child, Command, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use zbus::{connection::Builder, interface, message::Header};

struct Bus {
    child: Child,
    _directory: tempfile::TempDir,
    address: String,
}
impl Bus {
    fn open() -> io::Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("nestlink-clipboard-bus-")
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
        let result = (|| {
            let stdout = child
                .stdout
                .as_mut()
                .ok_or_else(|| io::Error::other("owned bus fixture pipe missing"))?;
            // SAFETY: borrowed child pipe, only its nonblocking status is changed.
            if unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let until = Instant::now() + Duration::from_secs(2);
            let mut bytes = Vec::new();
            while !bytes.contains(&b'\n') {
                if Instant::now() >= until || bytes.len() > 4096 {
                    return Err(timed_out("owned clipboard bus did not become ready"));
                }
                let mut buffer = [0; 256];
                match stdout.read(&mut buffer) {
                    Ok(0) => return Err(io::Error::other("owned clipboard bus exited")),
                    Ok(count) => bytes.extend_from_slice(&buffer[..count]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
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
struct State {
    requests: AtomicUsize,
    reads: AtomicUsize,
    writes: AtomicUsize,
    closes: AtomicUsize,
    started: AtomicBool,
    closed: AtomicBool,
    text: Vec<u8>,
    output: Mutex<Option<std::fs::File>>,
    received: Mutex<Option<Vec<u8>>>,
}
struct Extension(Arc<State>);
#[interface(name = "org.freedesktop.portal.Clipboard")]
impl Extension {
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
        if self.0.started.load(Ordering::SeqCst) {
            return Err(zbus::fdo::Error::Failed("session already started".into()));
        }
        let caller = header
            .sender()
            .ok_or_else(|| zbus::fdo::Error::Failed("caller absent".into()))?
            .as_str()
            .trim_start_matches(':')
            .replace('.', "_");
        if !session
            .as_str()
            .starts_with(&format!("{ROOT}/session/{caller}/"))
        {
            return Err(zbus::fdo::Error::AccessDenied("different caller".into()));
        }
        self.0.requests.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn selection_read(
        &self,
        _session: OwnedObjectPath,
        mime: String,
    ) -> zbus::fdo::Result<zbus::zvariant::OwnedFd> {
        if ![UTF8, PLAIN].contains(&mime.as_str()) || self.0.closed.load(Ordering::SeqCst) {
            return Err(zbus::fdo::Error::AccessDenied(
                "session or MIME unavailable".into(),
            ));
        }
        self.0.reads.fetch_add(1, Ordering::SeqCst);
        let mut file = tempfile::tempfile().map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        file.write_all(&self.0.text)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(OwnedFd::from(file).into())
    }
    async fn set_selection(
        &self,
        session: OwnedObjectPath,
        _options: Dict,
        #[zbus(connection)] connection: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<()> {
        self.0.writes.fetch_add(1, Ordering::SeqCst);
        let options = HashMap::from([
            (
                "mime_types",
                OwnedValue::try_from(Value::from(vec![UTF8, PLAIN]))
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?,
            ),
            ("session_is_owner", OwnedValue::from(true)),
        ]);
        connection
            .emit_signal(
                header.sender().map(|name| name.as_str()),
                ROOT,
                CLIPBOARD,
                "SelectionOwnerChanged",
                &(session, options),
            )
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }
    fn selection_write(
        &self,
        _session: OwnedObjectPath,
        _serial: u32,
    ) -> zbus::fdo::Result<zbus::zvariant::OwnedFd> {
        let file = tempfile::tempfile().map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        let shared = file
            .try_clone()
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        *self
            .0
            .output
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("fixture poisoned".into()))? = Some(shared);
        Ok(OwnedFd::from(file).into())
    }
    fn selection_write_done(
        &self,
        _session: OwnedObjectPath,
        _serial: u32,
        success: bool,
    ) -> zbus::fdo::Result<()> {
        if !success {
            return Err(zbus::fdo::Error::Failed(
                "fixture transfer did not complete".into(),
            ));
        }
        let mut output = self
            .0
            .output
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("fixture poisoned".into()))?;
        let file = output
            .as_mut()
            .ok_or_else(|| zbus::fdo::Error::Failed("fixture transfer FD absent".into()))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        let mut bytes = Vec::new();
        file.take((CLIPBOARD_TEXT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        *self
            .0
            .received
            .lock()
            .map_err(|_| zbus::fdo::Error::Failed("fixture poisoned".into()))? = Some(bytes);
        Ok(())
    }
}
struct Session(Arc<State>);
#[interface(name = "org.freedesktop.portal.Session")]
impl Session {
    fn close(&self) {
        self.0.closes.fetch_add(1, Ordering::SeqCst);
        self.0.closed.store(true, Ordering::SeqCst);
    }
}
struct Fixture {
    _bus: Bus,
    owner: Connection,
    client: Connection,
    session: OwnedObjectPath,
    state: Arc<State>,
    runtime: Arc<Runtime>,
}
impl Fixture {
    fn open(text: Vec<u8>) -> io::Result<Self> {
        let bus = Bus::open()?;
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()?,
        );
        let state = Arc::new(State {
            requests: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            started: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            text,
            output: Mutex::new(None),
            received: Mutex::new(None),
        });
        let (owner, client, session) = runtime.block_on(async {
            let owner = Builder::address(bus.address.as_str())
                .map_err(error)?
                .name(PORTAL)
                .map_err(error)?
                .serve_at(ROOT, Extension(state.clone()))
                .map_err(error)?
                .build()
                .await
                .map_err(error)?;
            let client = Builder::address(bus.address.as_str())
                .map_err(error)?
                .build()
                .await
                .map_err(error)?;
            let sender = client
                .unique_name()
                .ok_or_else(|| denied("fixture client lacks a unique name"))?
                .as_str()
                .trim_start_matches(':')
                .replace('.', "_");
            let session =
                OwnedObjectPath::try_from(format!("{ROOT}/session/{sender}/clipboard_fixture"))
                    .map_err(error)?;
            owner
                .object_server()
                .at(session.as_str(), Session(state.clone()))
                .await
                .map_err(error)?;
            Ok::<_, io::Error>((owner, client, session))
        })?;
        Ok(Self {
            _bus: bus,
            owner,
            client,
            session,
            state,
            runtime,
        })
    }
    fn prepare(&self) -> io::Result<PreparedPortalClipboard> {
        self.runtime
            .block_on(PreparedPortalClipboard::request_before_start(
                &self.client,
                self.owner
                    .unique_name()
                    .ok_or_else(|| denied("fixture owner lacks a unique name"))?
                    .as_str(),
                self.session.clone(),
                Instant::now() + Duration::from_secs(1),
            ))
    }
    fn device(&self) -> io::Result<(ClipboardDevice, crate::LocalClipboardApprovalControl)> {
        let prepared = self.prepare()?;
        self.state.started.store(true, Ordering::SeqCst);
        let facts = Arc::new(Facts {
            active: AtomicBool::new(true),
            client: self.client.clone(),
            owner: self
                .owner
                .unique_name()
                .ok_or_else(|| denied("fixture owner absent"))?
                .as_str()
                .to_owned(),
            session: self.session.clone(),
            runtime: self.runtime.clone(),
            closed: AtomicBool::new(false),
        });
        let grant = prepared.finish_start(true, facts)?;
        let (approval, control) =
            LocalClipboardApproval::approve_from_local_user(binding(), true, true)?;
        let device = PortalClipboard::open(grant, binding(), approval, authority())?;
        Ok((device, control))
    }
    fn transfer(&self, serial: u32) -> io::Result<()> {
        self.runtime.block_on(async {
            self.owner
                .emit_signal(
                    self.client.unique_name().map(|name| name.as_str()),
                    ROOT,
                    CLIPBOARD,
                    "SelectionTransfer",
                    &(self.session.clone(), UTF8, serial),
                )
                .await
                .map_err(error)
        })
    }
}
struct Facts {
    active: AtomicBool,
    client: Connection,
    owner: String,
    session: OwnedObjectPath,
    runtime: Arc<Runtime>,
    closed: AtomicBool,
}
impl PortalSessionFacts for Facts {
    fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }
    fn invalidate(&self) {
        self.active.store(false, Ordering::SeqCst);
    }
    fn wait_closed_until(&self, until: Instant) -> io::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.runtime.block_on(bounded(until, async {
            let proxy = Proxy::new(
                &self.client,
                self.owner.as_str(),
                self.session.as_str(),
                "org.freedesktop.portal.Session",
            )
            .await
            .map_err(error)?;
            proxy.call::<_, _, ()>("Close", &()).await.map_err(error)
        }))?;
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}
#[test]
fn private_bus_original_session_rpc_and_real_fd_roundtrip() -> io::Result<()> {
    let fixture = Fixture::open("fixture 中文🙂".as_bytes().to_vec())?;
    let (mut device, _approval) = fixture.device()?;
    assert_eq!(fixture.state.requests.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.state.reads.load(Ordering::SeqCst), 0);
    assert_eq!(device.read_text()?, Some("fixture 中文🙂".into()));
    device.write_text("incoming remote 中文🙂")?;
    fixture.transfer(19)?;
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(bytes) = &*fixture
            .state
            .received
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?
        {
            assert_eq!(bytes, "incoming remote 中文🙂".as_bytes());
            break;
        }
        if Instant::now() >= until {
            return Err(timed_out(
                "private portal did not receive its advertised selection",
            ));
        }
        thread::sleep(Duration::from_millis(2));
    }
    device.close()?;
    assert!(fixture.state.closed.load(Ordering::SeqCst));
    assert_eq!(fixture.state.closes.load(Ordering::SeqCst), 1);
    assert!(device.read_text().is_err());
    assert_eq!(
        device.monitor().status().cleanup,
        crate::ClipboardCleanup::Complete
    );
    Ok(())
}
#[test]
fn private_bus_rejects_other_callers_handle_and_start_denial() -> io::Result<()> {
    let fixture = Fixture::open(Vec::new())?;
    let other = fixture.runtime.block_on(async {
        Builder::address(fixture._bus.address.as_str())
            .map_err(error)?
            .build()
            .await
            .map_err(error)
    })?;
    assert!(
        fixture
            .runtime
            .block_on(PreparedPortalClipboard::request_before_start(
                &other,
                fixture
                    .owner
                    .unique_name()
                    .ok_or_else(|| denied("fixture owner absent"))?
                    .as_str(),
                fixture.session.clone(),
                Instant::now() + Duration::from_secs(1)
            ))
            .is_err()
    );
    assert_eq!(fixture.state.requests.load(Ordering::SeqCst), 0);
    let prepared = fixture.prepare()?;
    let facts = Arc::new(Facts {
        active: AtomicBool::new(true),
        client: fixture.client.clone(),
        owner: fixture
            .owner
            .unique_name()
            .ok_or_else(|| denied("fixture owner absent"))?
            .as_str()
            .into(),
        session: fixture.session.clone(),
        runtime: fixture.runtime.clone(),
        closed: AtomicBool::new(false),
    });
    assert!(prepared.finish_start(false, facts).is_err());
    assert_eq!(fixture.state.reads.load(Ordering::SeqCst), 0);
    Ok(())
}
#[test]
fn private_bus_oversized_text_never_escapes_bound() -> io::Result<()> {
    let fixture = Fixture::open(vec![b'x'; CLIPBOARD_TEXT_BYTES + 1])?;
    let (mut device, _approval) = fixture.device()?;
    assert!(device.read_text().is_err());
    assert_eq!(fixture.state.reads.load(Ordering::SeqCst), 1);
    device.close()
}
#[test]
fn owned_pipe_cancellation_discards_data_and_stalled_reader_has_fixed_deadline() -> io::Result<()> {
    let (context, approval) = context()?;
    let (reader, mut writer) = UnixStream::pair()?;
    writer.write_all(b"fixture-secret")?;
    approval.revoke_read();
    assert!(
        read_fd(
            reader.into(),
            &context,
            Instant::now() + Duration::from_secs(1)
        )
        .is_err()
    );
    let (context, _approval) = crate::tests::context()?;
    let (reader, _writer) = UnixStream::pair()?;
    let started = Instant::now();
    assert_eq!(
        read_fd(reader.into(), &context, started + Duration::from_millis(25))
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(started.elapsed() < Duration::from_millis(100));
    Ok(())
}
