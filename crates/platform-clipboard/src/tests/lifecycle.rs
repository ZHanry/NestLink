use super::*;

struct Gate {
    entered: Mutex<Option<mpsc::SyncSender<thread::ThreadId>>>,
    released: Mutex<bool>,
    wake: Condvar,
}
impl Gate {
    fn new() -> (Arc<Self>, mpsc::Receiver<thread::ThreadId>, Release) {
        let (entered, receiver) = mpsc::sync_channel(1);
        let gate = Arc::new(Self {
            entered: Mutex::new(Some(entered)),
            released: Mutex::new(false),
            wake: Condvar::new(),
        });
        (gate.clone(), receiver, Release(gate))
    }
    fn wait(&self) {
        if let Some(entered) = self
            .entered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = entered.try_send(thread::current().id());
        }
        let mut released = self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*released {
            released = self
                .wake
                .wait(released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
    fn release(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.wake.notify_all();
    }
}
struct Release(Arc<Gate>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct LifecycleBackend {
    inner: FixtureBackend,
    drop_gate: Option<Arc<Gate>>,
    reject_check: bool,
    reject_close: bool,
}
impl Backend for LifecycleBackend {
    fn check(&mut self, until: Instant) -> io::Result<()> {
        if self.reject_check {
            return Err(denied("fixture startup access denied"));
        }
        self.inner.check(until)
    }
    fn read(&mut self, context: &Context, until: Instant) -> io::Result<Option<Zeroizing<String>>> {
        self.inner.read(context, until)
    }
    fn write(&mut self, text: &str, context: &Context, until: Instant) -> io::Result<()> {
        self.inner.write(text, context, until)
    }
    fn service(&mut self, context: &Context, until: Instant) -> io::Result<()> {
        self.inner.service(context, until)
    }
    fn close(&mut self, until: Instant) -> io::Result<()> {
        self.inner.close(until)?;
        if self.reject_close {
            return Err(io::Error::other("fixture backend cleanup unproved"));
        }
        Ok(())
    }
}
impl Drop for LifecycleBackend {
    fn drop(&mut self) {
        if let Some(gate) = &self.drop_gate {
            gate.wait();
        }
    }
}

fn drop_blocked_device(
    fixture: Arc<Fixture>,
    gate: Arc<Gate>,
) -> io::Result<(ClipboardDevice, LocalClipboardApprovalControl)> {
    let (approval, control) =
        LocalClipboardApproval::approve_from_local_user(binding(), true, true)?;
    let clipboard = ClipboardDevice::open(binding(), approval, authority(), move |_| {
        Ok(Box::new(LifecycleBackend {
            inner: FixtureBackend(fixture),
            drop_gate: Some(gate),
            reject_check: false,
            reject_close: false,
        }))
    })?;
    Ok((clipboard, control))
}

fn worker_thread(shared: &Shared) -> io::Result<thread::ThreadId> {
    match &*shared
        .worker
        .lock()
        .map_err(|_| io::Error::other("fixture worker lock poisoned"))?
    {
        WorkerState::Running(worker) => Ok(worker.handle.thread().id()),
        _ => Err(io::Error::other(
            "fixture original worker is no longer owned",
        )),
    }
}

// Test observation after explicitly releasing the gate does not renew or
// retry the production cleanup deadline, whose failure must remain sticky.
fn observe_real_join(shared: &Shared, monitor: &ClipboardMonitor) -> io::Result<()> {
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        monitor.status();
        if shared.worker_joined() {
            return Ok(());
        }
        if Instant::now() >= until {
            return Err(timed_out(
                "fixture original worker did not join after release",
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn backend_close_success_cannot_complete_cleanup_while_backend_drop_is_blocked() -> io::Result<()> {
    let fixture = Arc::new(Fixture::default());
    let (gate, entered, _release) = Gate::new();
    let (mut clipboard, _control) = drop_blocked_device(fixture.clone(), gate.clone())?;
    let shared = clipboard.context.shared.clone();
    let monitor = clipboard.monitor();
    let original_worker = worker_thread(&shared)?;
    let caller = thread::spawn(move || {
        let result = clipboard.close();
        (clipboard, result)
    });
    assert_eq!(
        entered
            .recv_timeout(Duration::from_secs(2))
            .map_err(io::Error::other)?,
        original_worker
    );
    assert!(fixture.closed.load(Ordering::SeqCst));
    assert!(!fixture.dropped.load(Ordering::SeqCst));
    assert!(!shared.worker_joined());
    assert_eq!(worker_thread(&shared)?, original_worker);
    assert_eq!(monitor.status().cleanup, ClipboardCleanup::Pending);
    let (mut clipboard, result) = caller
        .join()
        .map_err(|_| io::Error::other("fixture close caller panicked"))?;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    let failed = monitor.status().cleanup;
    assert!(matches!(failed, ClipboardCleanup::Failed(_)));
    assert_eq!(worker_thread(&shared)?, original_worker);
    gate.release();
    observe_real_join(&shared, &monitor)?;
    assert!(fixture.dropped.load(Ordering::SeqCst));
    assert_eq!(monitor.status().cleanup, failed);
    assert!(clipboard.close().is_err());
    Ok(())
}

#[test]
fn startup_timeout_returns_inactive_owner_with_original_failure_and_same_worker() -> io::Result<()>
{
    let fixture = Arc::new(Fixture::default());
    let (gate, entered, _release) = Gate::new();
    let (approval, _control) =
        LocalClipboardApproval::approve_from_local_user(binding(), true, true)?;
    let blocked = gate.clone();
    let backend_fixture = fixture.clone();
    let mut clipboard = ClipboardDevice::open_with_budget(
        binding(),
        approval,
        authority(),
        Duration::from_millis(100),
        move |_| {
            blocked.wait();
            Ok(Box::new(FixtureBackend(backend_fixture)))
        },
    )?;
    let shared = clipboard.context.shared.clone();
    let monitor = clipboard.monitor();
    let original_worker = entered
        .recv_timeout(Duration::from_secs(2))
        .map_err(io::Error::other)?;
    assert_eq!(worker_thread(&shared)?, original_worker);
    assert!(!monitor.status().active);
    assert_eq!(
        clipboard.check().err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(clipboard.read_text().is_err());
    assert!(clipboard.write_text("must not reach the fixture").is_err());
    assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
    let deadline = shared.cleanup_deadline();
    let failed = monitor.status().cleanup;
    assert!(matches!(failed, ClipboardCleanup::Failed(_)));
    assert!(clipboard.close().is_err());
    assert_eq!(shared.cleanup_deadline(), deadline);
    assert_eq!(worker_thread(&shared)?, original_worker);
    gate.release();
    observe_real_join(&shared, &monitor)?;
    assert!(fixture.closed.load(Ordering::SeqCst));
    assert!(fixture.dropped.load(Ordering::SeqCst));
    assert_eq!(monitor.status().cleanup, failed);
    assert_eq!(
        clipboard.check().err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(shared.cleanup_deadline(), deadline);
    Ok(())
}

#[test]
fn device_drop_retains_same_worker_in_bounded_table_until_observed_real_join() -> io::Result<()> {
    let fixture = Arc::new(Fixture::default());
    let (gate, entered, _release) = Gate::new();
    let (mut clipboard, _control) = drop_blocked_device(fixture.clone(), gate.clone())?;
    let shared = clipboard.context.shared.clone();
    let monitor = clipboard.monitor();
    let original_worker = worker_thread(&shared)?;
    assert!(clipboard.close().is_err());
    assert_eq!(
        entered
            .recv_timeout(Duration::from_secs(2))
            .map_err(io::Error::other)?,
        original_worker
    );
    let failed = monitor.status().cleanup;
    let deadline = shared.cleanup_deadline();
    drop(clipboard);
    assert_eq!(worker_thread(&shared)?, original_worker);
    {
        let retained = RETAINED_WORKERS
            .lock()
            .map_err(|_| io::Error::other("fixture retained table poisoned"))?;
        assert!(retained.iter().any(|owner| Arc::ptr_eq(owner, &shared)));
        assert!(retained.len() <= CLIPBOARD_WORKER_LIMIT);
    }
    assert!(!fixture.dropped.load(Ordering::SeqCst));
    gate.release();
    observe_real_join(&shared, &monitor)?;
    assert!(fixture.dropped.load(Ordering::SeqCst));
    assert_eq!(shared.cleanup_deadline(), deadline);
    assert_eq!(monitor.status().cleanup, failed);
    assert!(
        !RETAINED_WORKERS
            .lock()
            .map_err(|_| io::Error::other("fixture retained table poisoned"))?
            .iter()
            .any(|owner| Arc::ptr_eq(owner, &shared))
    );
    Ok(())
}

#[test]
fn startup_backend_cleanup_failure_returns_inactive_joined_owner() -> io::Result<()> {
    let fixture = Arc::new(Fixture::default());
    let backend_fixture = fixture.clone();
    let (approval, _control) =
        LocalClipboardApproval::approve_from_local_user(binding(), true, true)?;
    let mut clipboard = ClipboardDevice::open(binding(), approval, authority(), move |_| {
        Ok(Box::new(LifecycleBackend {
            inner: FixtureBackend(backend_fixture),
            drop_gate: None,
            reject_check: true,
            reject_close: true,
        }))
    })?;
    assert!(clipboard.context.shared.worker_joined());
    assert!(fixture.dropped.load(Ordering::SeqCst));
    assert!(!clipboard.monitor().status().active);
    assert_eq!(
        clipboard.check().err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(
        clipboard.close().err().map(|error| error.kind()),
        Some(io::ErrorKind::Other)
    );
    assert!(matches!(
        clipboard.monitor().status().cleanup,
        ClipboardCleanup::Failed(_)
    ));
    assert!(clipboard.read_text().is_err());
    assert!(clipboard.write_text("inactive owner cannot write").is_err());
    assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn original_startup_failure_survives_blocked_backend_destruction() -> io::Result<()> {
    let fixture = Arc::new(Fixture::default());
    let backend_fixture = fixture.clone();
    let (gate, entered, _release) = Gate::new();
    let blocked = gate.clone();
    let (approval, _control) =
        LocalClipboardApproval::approve_from_local_user(binding(), true, true)?;
    let mut clipboard = ClipboardDevice::open_with_budget(
        binding(),
        approval,
        authority(),
        Duration::from_millis(100),
        move |_| {
            Ok(Box::new(LifecycleBackend {
                inner: FixtureBackend(backend_fixture),
                drop_gate: Some(blocked),
                reject_check: true,
                reject_close: false,
            }))
        },
    )?;
    let shared = clipboard.context.shared.clone();
    let monitor = clipboard.monitor();
    let original_worker = entered
        .recv_timeout(Duration::from_secs(2))
        .map_err(io::Error::other)?;
    assert_eq!(worker_thread(&shared)?, original_worker);
    assert_eq!(
        clipboard.check().err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(
        monitor.status().failure.map(|failure| failure.kind),
        Some(io::ErrorKind::PermissionDenied)
    );
    let failed = monitor.status().cleanup;
    assert!(matches!(failed, ClipboardCleanup::Failed(_)));
    assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
    assert!(!fixture.dropped.load(Ordering::SeqCst));
    gate.release();
    observe_real_join(&shared, &monitor)?;
    assert!(fixture.dropped.load(Ordering::SeqCst));
    assert_eq!(monitor.status().cleanup, failed);
    assert_eq!(
        clipboard.check().err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    Ok(())
}

#[test]
fn startup_error_returns_without_owner_only_after_callback_captures_are_dropped() -> io::Result<()>
{
    struct Capture(Arc<AtomicBool>);
    impl Drop for Capture {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let capture = Capture(dropped.clone());
    let (approval, _control) =
        LocalClipboardApproval::approve_from_local_user(binding(), true, true)?;
    let result = ClipboardDevice::open(binding(), approval, authority(), move |_| {
        let _capture = capture;
        Err(denied("fixture startup denied before backend"))
    });
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert!(dropped.load(Ordering::SeqCst));
    Ok(())
}
