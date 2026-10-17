//! XDG FileChooser works with the user's X11 or Wayland portal backend.
use super::SelectionKind;
use futures_util::StreamExt;
use rand_core::{OsRng, RngCore};
use std::{collections::HashMap, io, path::PathBuf, time::Duration};
use zbus::{
    Connection, Proxy,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};

const PORTAL: &str = "org.freedesktop.portal.Desktop";
const ROOT: &str = "/org/freedesktop/portal/desktop";
const REQUEST: &str = "org.freedesktop.portal.Request";
const BUDGET: Duration = Duration::from_secs(300);
const IPC: Duration = Duration::from_secs(3);

fn error<E>(_: E) -> io::Error {
    io::Error::other("the desktop file selector failed")
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid desktop selector reply")
}
async fn proxy<'a>(
    connection: &'a Connection,
    owner: &'a str,
    path: &'a str,
    interface: &'a str,
) -> io::Result<Proxy<'a>> {
    tokio::time::timeout(IPC, Proxy::new(connection, owner, path, interface))
        .await
        .map_err(error)?
        .map_err(error)
}

pub(super) async fn choose(kind: SelectionKind) -> io::Result<Option<PathBuf>> {
    choose_with_budget(kind, BUDGET).await
}

async fn choose_with_budget(kind: SelectionKind, budget: Duration) -> io::Result<Option<PathBuf>> {
    let connection = tokio::time::timeout(IPC, Connection::session())
        .await
        .map_err(error)?
        .map_err(error)?;
    let desktop = proxy(
        &connection,
        PORTAL,
        ROOT,
        "org.freedesktop.portal.FileChooser",
    )
    .await?;
    // Activate the desktop-owned service, then pin its unique name so a
    // replacement process cannot supply a response to this selection request.
    let _: u32 = tokio::time::timeout(IPC, desktop.get_property("version"))
        .await
        .map_err(error)?
        .map_err(error)?;
    let dbus = proxy(
        &connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await?;
    let owner: String = tokio::time::timeout(IPC, dbus.call("GetNameOwner", &(PORTAL,)))
        .await
        .map_err(error)?
        .map_err(error)?;
    if !owner.starts_with(':') {
        return Err(invalid());
    }
    let mut random = [0u8; 16];
    OsRng.fill_bytes(&mut random);
    let token = format!("nestlink_{:032x}", u128::from_le_bytes(random));
    let sender = connection
        .unique_name()
        .ok_or_else(invalid)?
        .as_str()
        .trim_start_matches(':')
        .replace('.', "_");
    let expected = format!("{ROOT}/request/{sender}/{token}");
    let response = proxy(&connection, &owner, &expected, REQUEST).await?;
    let mut signals = tokio::time::timeout(IPC, response.receive_signal("Response"))
        .await
        .map_err(error)?
        .map_err(error)?;
    let desktop = proxy(
        &connection,
        &owner,
        ROOT,
        "org.freedesktop.portal.FileChooser",
    )
    .await?;
    let options = HashMap::from([
        ("handle_token", Value::from(token.as_str())),
        ("modal", Value::from(false)),
        ("multiple", Value::from(false)),
        ("directory", Value::from(kind == SelectionKind::Folder)),
    ]);
    let result = tokio::time::timeout(budget, async {
        let actual: OwnedObjectPath =
            tokio::time::timeout(IPC, desktop.call("OpenFile", &("", "NestLink", options)))
                .await
                .map_err(error)?
                .map_err(error)?;
        if actual.as_str() != expected {
            return Err(invalid());
        }
        let message = signals.next().await.ok_or_else(invalid)?;
        if message.body().len() > 32 * 1024 {
            return Err(invalid());
        }
        let (code, mut values): (u32, HashMap<String, OwnedValue>) =
            message.body().deserialize().map_err(error)?;
        if code == 1 {
            return Ok(None);
        }
        if code != 0 || values.len() > 32 {
            return Err(invalid());
        }
        let uris: Vec<String> = values
            .remove("uris")
            .ok_or_else(invalid)?
            .try_into()
            .map_err(error)?;
        if uris.len() != 1 || uris[0].len() > super::MAX_SELECTION_PATH * 3 {
            return Err(invalid());
        }
        let uri = url::Url::parse(&uris[0]).map_err(error)?;
        if uri.scheme() != "file"
            || uri.query().is_some()
            || uri.fragment().is_some()
            || !uri.username().is_empty()
            || uri.password().is_some()
        {
            return Err(invalid());
        }
        uri.to_file_path().map(Some).map_err(error)
    })
    .await;
    // Close even on timeout/invalid response. This owns only the exact request
    // path subscribed before OpenFile, never another session's chooser.
    let _ = tokio::time::timeout(IPC, response.call::<_, _, ()>("Close", &())).await;
    let selected =
        result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "file selection expired"))?;
    drop(signals);
    drop(response);
    drop(desktop);
    drop(dbus);
    let _ = tokio::time::timeout(IPC, connection.close()).await;
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
        sync::{
            Arc, Mutex,
            atomic::{AtomicU8, Ordering},
            mpsc,
        },
        thread,
        time::Instant,
    };
    use tempfile::TempDir;
    use tokio::sync::watch;
    use zbus::{
        Connection,
        connection::Builder,
        interface,
        message::Header,
        zvariant::{OwnedObjectPath, OwnedValue, Value},
    };

    const TEST_CASE_ENV: &str = "NESTLINK_SELECTION_PORTAL_TEST_CASE";
    const TEST_ADDRESS_ENV: &str = "NESTLINK_SELECTION_PORTAL_TEST_ADDRESS";
    const TEST_RESULT: &str = "portal helper passed";
    const FIXTURE_PATH: &str = "/tmp/nestlink-selection-fixture-中";
    const FILE_URI: &str = "file:///tmp/nestlink-selection-fixture-%E4%B8%AD";

    #[derive(Clone, Copy)]
    enum ReplyMode {
        Success = 0,
        Cancel = 1,
        Timeout = 2,
    }

    #[derive(Default)]
    struct PortalState {
        mode: AtomicU8,
        requests: Mutex<Vec<String>>,
        closed: Mutex<Vec<String>>,
    }

    impl PortalState {
        fn requests(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn closed(&self) -> Vec<String> {
            self.closed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    type Options = HashMap<String, OwnedValue>;
    type Results = HashMap<String, OwnedValue>;

    struct FakePortal(Arc<PortalState>);

    #[interface(name = "org.freedesktop.portal.FileChooser")]
    impl FakePortal {
        #[zbus(property, name = "version")]
        fn version(&self) -> u32 {
            4
        }

        async fn open_file(
            &self,
            _app_id: &str,
            _parent_window: &str,
            options: Options,
            #[zbus(header)] header: Header<'_>,
            #[zbus(connection)] connection: &Connection,
        ) -> zbus::fdo::Result<OwnedObjectPath> {
            let caller = header
                .sender()
                .map(|name| name.as_str().to_owned())
                .ok_or_else(|| zbus::fdo::Error::AccessDenied("sender missing".into()))?;
            let sender = caller.trim_start_matches(':').replace('.', "_");
            let token = options
                .get("handle_token")
                .and_then(|value| <&str>::try_from(value).ok())
                .ok_or_else(|| zbus::fdo::Error::InvalidArgs("handle_token missing".into()))?;
            let path = format!("{ROOT}/request/{sender}/{token}");
            let mode = self.0.mode.load(Ordering::Acquire);
            self.0
                .requests
                .lock()
                .map_err(|_| zbus::fdo::Error::Failed("request list poisoned".into()))?
                .push(path.clone());
            connection
                .object_server()
                .at(
                    path.as_str(),
                    FakeRequest {
                        path: path.clone(),
                        state: self.0.clone(),
                    },
                )
                .await
                .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;

            // A prior request's cancellation is deliberately delivered first.
            // The production client must only accept the exact subscribed path.
            let stale_path = format!("{ROOT}/request/{sender}/old_request_token");
            let stale = Results::new();
            connection
                .emit_signal(
                    Some(caller.as_str()),
                    stale_path.as_str(),
                    REQUEST,
                    "Response",
                    &(1_u32, stale),
                )
                .await
                .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;

            if mode != ReplyMode::Timeout as u8 {
                let (code, results) = if mode == ReplyMode::Success as u8 {
                    let uris = vec![FILE_URI.to_owned()];
                    let value = OwnedValue::try_from(Value::from(uris))
                        .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
                    (0_u32, Results::from([("uris".to_owned(), value)]))
                } else {
                    (1_u32, Results::new())
                };
                connection
                    .emit_signal(
                        Some(caller.as_str()),
                        path.as_str(),
                        REQUEST,
                        "Response",
                        &(code, results),
                    )
                    .await
                    .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
            }
            OwnedObjectPath::try_from(path)
                .map_err(|error| zbus::fdo::Error::InvalidArgs(error.to_string()))
        }
    }

    struct FakeRequest {
        path: String,
        state: Arc<PortalState>,
    }

    #[interface(name = "org.freedesktop.portal.Request")]
    impl FakeRequest {
        fn close(&self) -> zbus::fdo::Result<()> {
            self.state
                .closed
                .lock()
                .map_err(|_| zbus::fdo::Error::Failed("close list poisoned".into()))?
                .push(self.path.clone());
            Ok(())
        }
    }

    struct PrivateBus {
        process: Child,
        _directory: TempDir,
        address: String,
    }

    impl PrivateBus {
        fn start() -> io::Result<Self> {
            let directory = tempfile::Builder::new()
                .prefix("nestlink-file-portal-")
                .tempdir()?;
            let requested_address = format!("unix:path={}", directory.path().join("bus").display());
            let mut process = Command::new("dbus-daemon")
                .args([
                    "--session",
                    "--nofork",
                    "--print-address=1",
                    "--address",
                    requested_address.as_str(),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?;
            let stdout = match process.stdout.take() {
                Some(stdout) => stdout,
                None => {
                    let _ = process.kill();
                    let _ = process.wait();
                    return Err(io::Error::other("private D-Bus address pipe missing"));
                }
            };
            let (address_tx, address_rx) = mpsc::sync_channel(1);
            let reader = match thread::Builder::new()
                .name("nestlink-private-bus-readiness".into())
                .spawn(move || {
                    let mut address = String::new();
                    let result = BufReader::new(stdout)
                        .read_line(&mut address)
                        .and_then(|_| {
                            if address.trim().is_empty() {
                                Err(io::Error::other(
                                    "private D-Bus daemon exited before readiness",
                                ))
                            } else {
                                Ok(address.trim().to_owned())
                            }
                        });
                    let _ = address_tx.send(result);
                }) {
                Ok(reader) => reader,
                Err(error) => {
                    let _ = process.kill();
                    let _ = process.wait();
                    return Err(error);
                }
            };
            let address = match address_rx.recv_timeout(Duration::from_secs(3)) {
                Ok(Ok(address)) => address,
                Ok(Err(error)) => {
                    let _ = process.kill();
                    let _ = process.wait();
                    let _ = reader.join();
                    return Err(error);
                }
                Err(error) => {
                    let _ = process.kill();
                    let _ = process.wait();
                    let _ = reader.join();
                    return Err(io::Error::other(format!(
                        "private D-Bus daemon startup failed: {error}"
                    )));
                }
            };
            match reader.join() {
                Ok(()) => {}
                Err(_) => {
                    let _ = process.kill();
                    let _ = process.wait();
                    return Err(io::Error::other("private D-Bus readiness worker panicked"));
                }
            }
            Ok(Self {
                process,
                _directory: directory,
                address,
            })
        }
    }

    impl Drop for PrivateBus {
        fn drop(&mut self) {
            let _ = self.process.kill();
            let _ = self.process.wait();
        }
    }

    struct PortalFixture {
        state: Arc<PortalState>,
        shutdown: watch::Sender<bool>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl PortalFixture {
        fn start(address: &str) -> io::Result<Self> {
            let state = Arc::new(PortalState::default());
            let service_state = state.clone();
            let service_address = address.to_owned();
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let ready_error = ready_tx.clone();
            let (shutdown, mut stopped) = watch::channel(false);
            let worker = thread::Builder::new()
                .name("nestlink-fake-file-portal".into())
                .spawn(move || {
                    let result = (|| -> io::Result<()> {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        runtime.block_on(async {
                            let server = Builder::address(service_address.as_str())
                                .map_err(|error| io::Error::other(error.to_string()))?
                                .name(PORTAL)
                                .map_err(|error| io::Error::other(error.to_string()))?
                                .serve_at(ROOT, FakePortal(service_state))
                                .map_err(|error| io::Error::other(error.to_string()))?
                                .build()
                                .await
                                .map_err(|error| io::Error::other(error.to_string()))?;
                            let _ = ready_tx.send(Ok(()));
                            let _ = stopped.changed().await;
                            let _ = tokio::time::timeout(IPC, server.close()).await;
                            Ok(())
                        })
                    })();
                    if let Err(error) = result {
                        let _ = ready_error.send(Err(error.to_string()));
                    }
                })?;
            match ready_rx.recv_timeout(Duration::from_secs(3)) {
                Ok(Ok(())) => Ok(Self {
                    state,
                    shutdown,
                    worker: Some(worker),
                }),
                Ok(Err(message)) => {
                    let _ = shutdown.send(true);
                    let _ = worker.join();
                    Err(io::Error::other(message))
                }
                Err(error) => {
                    let _ = shutdown.send(true);
                    let _ = worker.join();
                    Err(io::Error::other(format!(
                        "fake portal startup failed: {error}"
                    )))
                }
            }
        }
    }

    impl Drop for PortalFixture {
        fn drop(&mut self) {
            let _ = self.shutdown.send(true);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn run_helper(case: &str, address: &str) -> io::Result<()> {
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "selection::linux::tests::portal_helper_subprocess",
                "--nocapture",
            ])
            .env(TEST_CASE_ENV, case)
            .env(TEST_ADDRESS_ENV, address)
            // This is scoped to the helper process; the test runner and other
            // concurrently executing tests keep their original session bus.
            .env("DBUS_SESSION_BUS_ADDRESS", address)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if child.try_wait()?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output()?;
                return Err(io::Error::other(format!(
                    "portal helper timed out: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "portal helper failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains(&format!("{TEST_RESULT}: {case}")) {
            return Err(io::Error::other(
                "portal helper did not run its production assertion",
            ));
        }
        Ok(())
    }

    #[test]
    fn portal_helper_subprocess() {
        let Ok(case) = std::env::var(TEST_CASE_ENV) else {
            return;
        };
        let address = std::env::var(TEST_ADDRESS_ENV)
            .unwrap_or_else(|error| panic!("private test bus address missing: {error}"));
        let result = match case.as_str() {
            "success" => crate::selection::choose(SelectionKind::File),
            "cancel" => crate::selection::choose(SelectionKind::Folder),
            "timeout" => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap_or_else(|error| panic!("test runtime failed: {error}"));
                runtime.block_on(choose_with_budget(
                    SelectionKind::File,
                    Duration::from_millis(150),
                ))
            }
            _ => panic!("unknown portal helper case"),
        };
        match case.as_str() {
            "success" => assert_eq!(
                result.unwrap_or_else(|error| panic!("choose failed: {error}")),
                Some(PathBuf::from(FIXTURE_PATH))
            ),
            "cancel" => assert_eq!(
                result.unwrap_or_else(|error| panic!("choose failed: {error}")),
                None
            ),
            "timeout" => assert_eq!(
                result.err().map(|error| error.kind()),
                Some(io::ErrorKind::TimedOut)
            ),
            _ => unreachable!(),
        }
        assert_eq!(
            std::env::var("DBUS_SESSION_BUS_ADDRESS").as_deref(),
            Ok(address.as_str())
        );
        println!("{TEST_RESULT}: {case}");
    }

    #[test]
    fn private_portal_isolates_request_signals_and_closes_each_request() -> io::Result<()> {
        let bus = match PrivateBus::start() {
            Ok(bus) => bus,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                eprintln!("dbus-daemon is unavailable; skipping isolated portal fixture");
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let fixture = PortalFixture::start(&bus.address)?;

        for (case, mode) in [
            ("success", ReplyMode::Success),
            ("cancel", ReplyMode::Cancel),
            ("timeout", ReplyMode::Timeout),
        ] {
            fixture.state.mode.store(mode as u8, Ordering::Release);
            run_helper(case, &bus.address)?;
        }

        let requests = fixture.state.requests();
        let closed = fixture.state.closed();
        assert_eq!(
            requests.len(),
            3,
            "all helper requests reached the fake portal"
        );
        assert_eq!(
            closed, requests,
            "Close must target each exact request path"
        );
        Ok(())
    }
}
