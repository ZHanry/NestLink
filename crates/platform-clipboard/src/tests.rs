use super::*;
use std::sync::atomic::AtomicUsize;

mod lifecycle;

pub(crate) fn binding() -> ClipboardBinding {
    ClipboardBinding {
        session_id: "14a101b4-c37d-442d-ad7a-22e63b99c5ac".into(),
        connection_generation: 7,
    }
}
pub(crate) struct Authority {
    pub(crate) active: AtomicBool,
}
impl ClipboardAuthority for Authority {
    fn check(&self, binding: &ClipboardBinding, _: ClipboardDirection) -> io::Result<()> {
        if *binding != self::binding() || !self.active.load(Ordering::SeqCst) {
            return Err(denied("fixture current session lease ended"));
        }
        Ok(())
    }
}
pub(crate) fn authority() -> Arc<Authority> {
    Arc::new(Authority {
        active: AtomicBool::new(true),
    })
}
pub(crate) fn context() -> io::Result<(Context, LocalClipboardApprovalControl)> {
    let (approval, control) =
        LocalClipboardApproval::approve_from_local_user(binding(), true, true)?;
    let context = Context {
        binding: binding(),
        approval: approval.0,
        authority: authority(),
        shared: Arc::new(Shared::new()),
    };
    Ok((context, control))
}
struct Fixture {
    reads: AtomicUsize,
    writes: AtomicUsize,
    closed: AtomicBool,
    dropped: AtomicBool,
    system_active: AtomicBool,
    started: Mutex<Option<mpsc::SyncSender<()>>>,
    read_delay: Duration,
    write_delay: Duration,
}
impl Default for Fixture {
    fn default() -> Self {
        Self {
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            dropped: AtomicBool::new(false),
            system_active: AtomicBool::new(true),
            started: Mutex::new(None),
            read_delay: Duration::ZERO,
            write_delay: Duration::ZERO,
        }
    }
}
struct FixtureBackend(Arc<Fixture>);
impl Drop for FixtureBackend {
    fn drop(&mut self) {
        self.0.dropped.store(true, Ordering::SeqCst);
    }
}
impl Backend for FixtureBackend {
    fn check(&mut self, _: Instant) -> io::Result<()> {
        if !self.0.system_active.load(Ordering::SeqCst) {
            return Err(denied("fixture OS session lost"));
        }
        Ok(())
    }
    fn read(&mut self, context: &Context, until: Instant) -> io::Result<Option<Zeroizing<String>>> {
        self.0.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(started) = self
            .0
            .started
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?
            .take()
        {
            let _ = started.try_send(());
        }
        std::thread::sleep(self.0.read_delay);
        context.check(ClipboardDirection::Read, until)?;
        Ok(Some(Zeroizing::new("fixture 中文🙂".into())))
    }
    fn write(&mut self, _: &str, context: &Context, until: Instant) -> io::Result<()> {
        if let Some(started) = self
            .0
            .started
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?
            .take()
        {
            let _ = started.try_send(());
        }
        std::thread::sleep(self.0.write_delay);
        context.check(ClipboardDirection::Write, until)?;
        self.0.writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn service(&mut self, _: &Context, _: Instant) -> io::Result<()> {
        Ok(())
    }
    fn close(&mut self, _: Instant) -> io::Result<()> {
        self.0.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}
fn device(
    fixture: Arc<Fixture>,
    read: bool,
    write: bool,
) -> io::Result<(
    ClipboardDevice,
    LocalClipboardApprovalControl,
    Arc<Authority>,
)> {
    let (approval, control) =
        LocalClipboardApproval::approve_from_local_user(binding(), read, write)?;
    let authority = authority();
    let device = ClipboardDevice::open(binding(), approval, authority.clone(), move |_| {
        Ok(Box::new(FixtureBackend(fixture)))
    })?;
    Ok((device, control, authority))
}
#[test]
fn opens_without_reading_and_directions_require_separate_local_approval() -> io::Result<()> {
    let fixture = Arc::new(Fixture::default());
    let (mut clipboard, _control, _authority) = device(fixture.clone(), false, true)?;
    clipboard.check()?;
    assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
    assert_eq!(
        clipboard.read_text().err().map(|e| e.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
    clipboard.write_text("")?;
    clipboard.write_text("new text 中文🙂")?;
    assert_eq!(fixture.writes.load(Ordering::SeqCst), 2);
    clipboard.close()?;
    assert!(fixture.closed.load(Ordering::SeqCst));
    assert!(fixture.dropped.load(Ordering::SeqCst));
    assert!(clipboard.context.shared.worker_joined());
    assert_eq!(
        clipboard.monitor().status().cleanup,
        ClipboardCleanup::Complete
    );
    assert!(clipboard.write_text("old session").is_err());
    assert_eq!(fixture.writes.load(Ordering::SeqCst), 2);
    Ok(())
}
#[test]
fn invalid_and_oversized_text_never_reaches_platform() -> io::Result<()> {
    let fixture = Arc::new(Fixture::default());
    let (mut clipboard, _control, _authority) = device(fixture.clone(), true, true)?;
    assert!(clipboard.write_text("nul\0text").is_err());
    assert!(
        clipboard
            .write_text(&"中".repeat(CLIPBOARD_TEXT_BYTES / 3 + 1))
            .is_err()
    );
    assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
    clipboard.close()
}
#[test]
fn local_owner_drop_ends_idle_worker_and_cannot_restore_consent() -> io::Result<()> {
    let fixture = Arc::new(Fixture::default());
    let (mut clipboard, control, _authority) = device(fixture.clone(), true, true)?;
    let monitor = clipboard.monitor();
    drop(control);
    monitor.wait_cleanup_until(Instant::now() + Duration::from_secs(1))?;
    assert!(!monitor.status().active);
    assert!(clipboard.read_text().is_err());
    assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
    clipboard.close()
}
#[test]
fn queued_text_guard_rechecks_its_direction_and_original_deadline() -> io::Result<()> {
    let fixture = Arc::new(Fixture::default());
    let (mut clipboard, control, authority) = device(fixture, true, true)?;
    let read = clipboard.direction_guard(ClipboardDirection::Read);
    let write = clipboard.direction_guard(ClipboardDirection::Write);
    let pending = clipboard.read_text()?;
    assert!(pending.is_some());
    read.check()?;
    control.revoke_read();
    assert_eq!(
        read.check().err().map(|e| e.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    write.check()?;
    clipboard.write_text("write remains separately approved")?;
    assert_eq!(
        write.check_until(Instant::now()).err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    authority.active.store(false, Ordering::SeqCst);
    assert!(write.check().is_err());
    clipboard.close()?;
    authority.active.store(true, Ordering::SeqCst);
    assert!(write.check().is_err());
    Ok(())
}
#[test]
fn direction_revoked_during_business_observation_cannot_pass_delivery_guard() -> io::Result<()> {
    struct PausedAuthority {
        entered: mpsc::SyncSender<()>,
        resume: Mutex<mpsc::Receiver<()>>,
    }
    impl ClipboardAuthority for PausedAuthority {
        fn check(&self, _: &ClipboardBinding, _: ClipboardDirection) -> io::Result<()> {
            self.entered.send(()).map_err(io::Error::other)?;
            self.resume
                .lock()
                .map_err(|_| io::Error::other("fixture poisoned"))?
                .recv_timeout(Duration::from_secs(1))
                .map_err(io::Error::other)
        }
    }
    let (mut context, control) = context()?;
    let (entered, observing) = mpsc::sync_channel(1);
    let (resume, resumed) = mpsc::sync_channel(1);
    context.authority = Arc::new(PausedAuthority {
        entered,
        resume: Mutex::new(resumed),
    });
    let guard = ClipboardDirectionGuard {
        context,
        direction: ClipboardDirection::Read,
    };
    let pending = thread::spawn(move || guard.check());
    observing
        .recv_timeout(Duration::from_secs(1))
        .map_err(io::Error::other)?;
    control.revoke_read();
    resume.send(()).map_err(io::Error::other)?;
    assert_eq!(
        pending
            .join()
            .map_err(|_| io::Error::other("guard fixture panicked"))?
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    Ok(())
}
#[test]
fn lease_loss_and_os_loss_stop_idle_workers() -> io::Result<()> {
    for business_loss in [false, true] {
        let fixture = Arc::new(Fixture::default());
        let (mut clipboard, _control, authority) = device(fixture.clone(), true, true)?;
        if business_loss {
            authority.active.store(false, Ordering::SeqCst);
        } else {
            fixture.system_active.store(false, Ordering::SeqCst);
        }
        clipboard
            .monitor()
            .wait_cleanup_until(Instant::now() + Duration::from_secs(1))?;
        assert_eq!(
            clipboard
                .monitor()
                .status()
                .failure
                .map(|failure| failure.kind),
            Some(io::ErrorKind::PermissionDenied)
        );
        assert!(clipboard.read_text().is_err());
        authority.active.store(true, Ordering::SeqCst);
        fixture.system_active.store(true, Ordering::SeqCst);
        assert!(clipboard.write_text("cannot resurrect").is_err());
        clipboard.close()?;
    }
    Ok(())
}
#[test]
fn local_revocation_during_read_never_discloses_fixture_text() -> io::Result<()> {
    let (started, signal) = mpsc::sync_channel(1);
    let fixture = Arc::new(Fixture {
        read_delay: Duration::from_millis(80),
        started: Mutex::new(Some(started)),
        ..Fixture::default()
    });
    let (mut clipboard, control, _authority) = device(fixture.clone(), true, true)?;
    let task = std::thread::spawn(move || {
        let result = clipboard.read_text();
        let _ = clipboard.close();
        result
    });
    signal
        .recv_timeout(Duration::from_secs(1))
        .map_err(io::Error::other)?;
    control.revoke_read();
    assert_eq!(
        task.join()
            .map_err(|_| io::Error::other("read fixture panicked"))?
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(fixture.reads.load(Ordering::SeqCst), 1);
    Ok(())
}
#[test]
fn deadline_is_not_renewed_and_late_write_is_discarded() -> io::Result<()> {
    let fixture = Arc::new(Fixture {
        write_delay: Duration::from_millis(400),
        ..Fixture::default()
    });
    let (mut clipboard, _control, _authority) = device(fixture.clone(), true, true)?;
    let monitor = clipboard.monitor();
    let started = Instant::now();
    assert_eq!(
        clipboard.write_text("pending text").err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(started.elapsed() < Duration::from_millis(370));
    assert!(!monitor.status().active);
    monitor.wait_cleanup_until(Instant::now() + Duration::from_secs(1))?;
    assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
    assert_eq!(
        monitor.status().failure.map(|failure| failure.kind),
        Some(io::ErrorKind::TimedOut)
    );
    clipboard.close()
}
#[test]
fn wrong_local_binding_fails_before_starting_native_worker() -> io::Result<()> {
    let (approval, _control) =
        LocalClipboardApproval::approve_from_local_user(binding(), true, true)?;
    let mut different = binding();
    different.connection_generation += 1;
    let opened = Arc::new(AtomicBool::new(false));
    let seen = opened.clone();
    assert!(
        ClipboardDevice::open(different, approval, authority(), move |_| {
            seen.store(true, Ordering::SeqCst);
            Ok(Box::new(FixtureBackend(Arc::new(Fixture::default()))))
        })
        .is_err()
    );
    assert!(!opened.load(Ordering::SeqCst));
    Ok(())
}
