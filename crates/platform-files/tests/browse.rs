use nestlink_auth::random_id;
use nestlink_platform_files::browse::{
    ApprovedBrowseRoot, BrowseConsent, BrowseEntryKind, BrowseLimits, BrowseSelection,
    BrowseTicket, DIRECTORY_CURSOR_LIFETIME, DIRECTORY_MAX_ENTRIES, DIRECTORY_MAX_NAME_BYTES,
    DIRECTORY_OPERATION_BUDGET, DIRECTORY_PAGE_ENTRIES, DirectoryMonitor, DirectoryShutdown,
    DirectoryWorker,
};
use std::{
    fs, io,
    path::Path,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn approved(path: &Path, limits: BrowseLimits) -> Result<(ApprovedBrowseRoot, BrowseConsent)> {
    let (selection, consent) = BrowseSelection::new(&random_id(), path, limits)?;
    Ok((selection.open(&mut || Ok(()))?, consent))
}
fn wait<T>(ticket: &mut BrowseTicket<T>) -> Result<T> {
    let started = Instant::now();
    loop {
        if let Some(result) = ticket.try_result()? {
            return Ok(result);
        }
        if started.elapsed() >= Duration::from_secs(2) {
            return Err("directory ticket did not complete".into());
        }
        thread::sleep(Duration::from_millis(2));
    }
}
fn stopped(worker: &mut DirectoryWorker) -> Result {
    let started = Instant::now();
    while worker.poll_shutdown() != DirectoryShutdown::Finished {
        if started.elapsed() >= Duration::from_secs(2) {
            return Err("directory worker did not actually finish".into());
        }
        thread::sleep(Duration::from_millis(2));
    }
    assert!(worker.monitor().status().handles_closed);
    Ok(())
}
fn until_finished(monitor: &DirectoryMonitor) -> Result {
    let started = Instant::now();
    while !monitor.status().finished {
        if started.elapsed() >= Duration::from_secs(2) {
            return Err("directory monitor did not observe actual teardown".into());
        }
        thread::sleep(Duration::from_millis(2));
    }
    assert!(monitor.status().handles_closed);
    Ok(())
}
#[cfg(unix)]
fn directory_link(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}
#[cfg(windows)]
fn directory_link(target: &Path, link: &Path) -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    let result = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", "New-Item -ItemType Junction -Path $env:NESTLINK_BROWSE_TEST_LINK -Value $env:NESTLINK_BROWSE_TEST_TARGET -ErrorAction Stop | Out-Null"])
        .env("NESTLINK_BROWSE_TEST_LINK", link).env("NESTLINK_BROWSE_TEST_TARGET", target)
        .creation_flags(0x0800_0000).output()?;
    if !result.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&result.stderr).into_owned(),
        ));
    }
    Ok(())
}

#[test]
fn real_directory_metadata_has_sorted_bounded_pages_and_distinct_file_types() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("a"), b"abc")?;
    fs::create_dir(dir.path().join("nested"))?;
    fs::write(dir.path().join("nested/inner"), b"nested data")?;
    fs::write(dir.path().join("中文.txt"), b"")?;
    let (mut root, _consent) = approved(dir.path(), BrowseLimits::default())?;
    let id = root.id().to_owned();
    let first = root.begin(None, 1, &mut || Ok(()))?;
    assert_eq!(first.root_id, id);
    assert_eq!(first.directory, None);
    assert_eq!(first.total_entries, 3);
    assert_eq!(first.entries.len(), 1);
    assert_eq!(first.entries[0].name, "a");
    assert_eq!(first.entries[0].kind, BrowseEntryKind::File);
    assert_eq!(first.entries[0].size, Some(3));
    let second = root.next(
        &first.next.ok_or("missing first cursor")?,
        1,
        &mut || Ok(()),
    )?;
    assert_eq!(second.entries[0].name, "nested");
    assert_eq!(second.entries[0].kind, BrowseEntryKind::Directory);
    assert_eq!(second.entries[0].size, None);
    let third = root.next(&second.next.ok_or("missing second cursor")?, 1, &mut || {
        Ok(())
    })?;
    assert_eq!(third.entries[0].name, "中文.txt");
    assert_eq!(third.entries[0].size, Some(0));
    assert!(third.next.is_none());
    let nested = root.begin(Some("nested"), DIRECTORY_PAGE_ENTRIES, &mut || Ok(()))?;
    assert_eq!(nested.directory.as_deref(), Some("nested"));
    assert_eq!(nested.entries[0].name, "inner");
    assert_eq!(nested.entries[0].size, Some(11));
    root.retire();
    Ok(())
}

#[test]
fn portable_paths_page_sizes_and_hard_limits_cannot_be_relaxed() -> Result {
    let dir = tempfile::tempdir()?;
    let (mut root, _consent) = approved(dir.path(), BrowseLimits::default())?;
    for path in [
        "",
        "../secret",
        "/etc",
        "C:/Windows",
        "a\\b",
        "a//b",
        "a:stream",
        "NUL",
        "a/.",
    ] {
        assert!(root.begin(Some(path), 1, &mut || Ok(())).is_err(), "{path}");
    }
    for maximum in [0, DIRECTORY_PAGE_ENTRIES + 1, usize::MAX] {
        assert!(root.begin(None, maximum, &mut || Ok(())).is_err());
    }
    assert!(BrowseSelection::new("invalid", dir.path(), BrowseLimits::default()).is_err());
    assert!(
        BrowseSelection::new(&random_id(), Path::new("relative"), BrowseLimits::default()).is_err()
    );
    for (entries, names, operation, lifetime) in [
        (0, 1, Duration::from_secs(1), Duration::from_secs(1)),
        (
            DIRECTORY_MAX_ENTRIES + 1,
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        (1, 0, Duration::from_secs(1), Duration::from_secs(1)),
        (
            1,
            DIRECTORY_MAX_NAME_BYTES + 1,
            Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        (1, 1, Duration::ZERO, Duration::from_secs(1)),
        (
            1,
            1,
            DIRECTORY_OPERATION_BUDGET + Duration::from_nanos(1),
            Duration::from_secs(1),
        ),
        (1, 1, Duration::from_secs(1), Duration::ZERO),
        (
            1,
            1,
            Duration::from_secs(1),
            DIRECTORY_CURSOR_LIFETIME + Duration::from_nanos(1),
        ),
    ] {
        assert!(BrowseLimits::new(entries, names, operation, lifetime).is_err());
    }
    Ok(())
}

#[test]
fn cursors_bind_the_actual_root_handle_snapshot_and_expected_offset() -> Result {
    let dir = tempfile::tempdir()?;
    for name in ["a", "b", "c"] {
        fs::write(dir.path().join(name), b"")?;
    }
    let (selection, _first_consent) =
        BrowseSelection::new(&random_id(), dir.path(), BrowseLimits::default())?;
    let mut root = selection.open(&mut || Ok(()))?;
    let (selection, _second_consent) =
        BrowseSelection::new(root.id(), dir.path(), BrowseLimits::default())?;
    let mut other = selection.open(&mut || Ok(()))?;
    let first = root.begin(None, 1, &mut || Ok(()))?;
    let cursor = first.next.ok_or("missing cursor")?;
    other.begin(None, 1, &mut || Ok(()))?;
    assert!(
        other.next(&cursor, 1, &mut || Ok(())).is_err(),
        "same root ID/path grants no cursor authority"
    );
    let second = root.next(&cursor, 1, &mut || Ok(()))?;
    assert_eq!(second.entries[0].name, "b");
    assert!(
        root.next(&cursor, 1, &mut || Ok(())).is_err(),
        "replayed offset must be rejected"
    );
    assert!(
        root.next(
            &second.next.ok_or("missing next cursor")?,
            1,
            &mut || Ok(())
        )
        .is_err(),
        "failed cursor retires the snapshot"
    );
    let old = root
        .begin(None, 1, &mut || Ok(()))?
        .next
        .ok_or("missing old cursor")?;
    root.begin(None, 1, &mut || Ok(()))?;
    assert!(
        root.next(&old, 1, &mut || Ok(())).is_err(),
        "refresh must invalidate old snapshot identity"
    );
    Ok(())
}

#[test]
fn observed_directory_or_file_metadata_changes_require_a_fresh_browse() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("a"), b"a")?;
    fs::write(dir.path().join("b"), b"b")?;
    let (mut root, _consent) = approved(dir.path(), BrowseLimits::default())?;
    let cursor = root
        .begin(None, 1, &mut || Ok(()))?
        .next
        .ok_or("missing cursor")?;
    fs::write(dir.path().join("c"), b"c")?;
    let error = root
        .next(&cursor, 1, &mut || Ok(()))
        .err()
        .ok_or("changed directory returned a mixed page")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("fresh browse"));
    let cursor = root
        .begin(None, 1, &mut || Ok(()))?
        .next
        .ok_or("missing refreshed cursor")?;
    fs::write(dir.path().join("b"), b"changed-length")?;
    assert_eq!(
        root.next(&cursor, 1, &mut || Ok(()))
            .err()
            .ok_or("changed file metadata was accepted")?
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        root.begin(None, 3, &mut || Ok(()))?.entries[1].size,
        Some(14)
    );
    let mut calls = 0;
    let error = root
        .begin(None, 2, &mut || {
            calls += 1;
            if calls == 7 {
                fs::write(dir.path().join("during"), b"mutation")?;
            }
            Ok(())
        })
        .err()
        .ok_or("mutation during a bounded scan was accepted")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    Ok(())
}

#[test]
fn replacing_the_local_selected_path_cannot_replace_the_pinned_root() -> Result {
    let dir = tempfile::tempdir()?;
    let selected = dir.path().join("selected");
    fs::create_dir(&selected)?;
    fs::write(selected.join("original"), b"original")?;
    let (mut root, _consent) = approved(&selected, BrowseLimits::default())?;
    #[cfg(unix)]
    {
        fs::rename(&selected, dir.path().join("moved"))?;
        fs::create_dir(&selected)?;
        fs::write(selected.join("replacement"), b"replacement")?;
    }
    #[cfg(windows)]
    {
        assert_eq!(
            fs::rename(&selected, dir.path().join("moved"))
                .err()
                .ok_or("pinned Windows root was movable")?
                .raw_os_error(),
            Some(32)
        );
    }
    assert_eq!(
        root.begin(None, 1, &mut || Ok(()))?.entries[0].name,
        "original"
    );
    Ok(())
}

#[test]
fn links_reparse_points_and_multilink_files_fail_without_returning_a_partial_page() -> Result {
    let outside = tempfile::tempdir()?;
    fs::write(outside.path().join("secret"), b"secret")?;
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("allowed"), b"allowed")?;
    directory_link(outside.path(), &dir.path().join("linked"))?;
    let (selection, _selection_consent) = BrowseSelection::new(
        &random_id(),
        &dir.path().join("linked"),
        BrowseLimits::default(),
    )?;
    assert!(
        selection.open(&mut || Ok(())).is_err(),
        "selected root itself cannot be a final-component link"
    );
    let (mut root, _consent) = approved(dir.path(), BrowseLimits::default())?;
    assert!(root.begin(None, 1, &mut || Ok(())).is_err());
    assert!(root.begin(Some("linked"), 1, &mut || Ok(())).is_err());
    let hard = tempfile::tempdir()?;
    fs::hard_link(
        outside.path().join("secret"),
        hard.path().join("hardlinked"),
    )?;
    let (mut root, _consent) = approved(hard.path(), BrowseLimits::default())?;
    assert_eq!(
        root.begin(None, 1, &mut || Ok(()))
            .err()
            .ok_or("hardlinked file was disclosed")?
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    #[cfg(unix)]
    {
        let links = tempfile::tempdir()?;
        std::os::unix::fs::symlink(
            outside.path().join("secret"),
            links.path().join("file-link"),
        )?;
        let (mut root, _consent) = approved(links.path(), BrowseLimits::default())?;
        assert!(root.begin(None, 1, &mut || Ok(())).is_err());
    }
    assert_eq!(fs::read(outside.path().join("secret"))?, b"secret");
    Ok(())
}

#[test]
fn entry_and_name_limits_fail_the_whole_scan_instead_of_truncating_a_directory() -> Result {
    let dir = tempfile::tempdir()?;
    for name in ["aaaa", "bbbb", "cccc", "dddd"] {
        fs::write(dir.path().join(name), b"")?;
    }
    let limits = BrowseLimits::new(
        3,
        1024,
        DIRECTORY_OPERATION_BUDGET,
        DIRECTORY_CURSOR_LIFETIME,
    )?;
    let (mut root, _consent) = approved(dir.path(), limits)?;
    assert_eq!(
        root.begin(None, 1, &mut || Ok(()))
            .err()
            .ok_or("oversized directory was truncated")?
            .kind(),
        io::ErrorKind::FileTooLarge
    );
    let limits = BrowseLimits::new(
        100,
        6,
        DIRECTORY_OPERATION_BUDGET,
        DIRECTORY_CURSOR_LIFETIME,
    )?;
    let (mut root, _consent) = approved(dir.path(), limits)?;
    assert_eq!(
        root.begin(None, 1, &mut || Ok(()))
            .err()
            .ok_or("name budget was ignored")?
            .kind(),
        io::ErrorKind::FileTooLarge
    );
    Ok(())
}

#[test]
fn a_real_directory_larger_than_the_default_limit_is_rejected_as_a_whole() -> Result {
    let dir = tempfile::tempdir()?;
    for index in 0..=DIRECTORY_MAX_ENTRIES {
        fs::write(dir.path().join(format!("entry-{index:04}")), b"")?;
    }
    let (mut root, _consent) = approved(dir.path(), BrowseLimits::default())?;
    assert_eq!(
        root.begin(None, 1, &mut || Ok(()))
            .err()
            .ok_or("4097-entry directory was silently truncated")?
            .kind(),
        io::ErrorKind::FileTooLarge
    );
    Ok(())
}

#[test]
fn root_owner_revocation_drop_and_current_authorization_invalidate_pages() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("a"), b"a")?;
    fs::write(dir.path().join("b"), b"b")?;
    let (mut root, consent) = approved(dir.path(), BrowseLimits::default())?;
    let cursor = root
        .begin(None, 1, &mut || Ok(()))?
        .next
        .ok_or("missing cursor")?;
    consent.revoke();
    assert_eq!(
        root.next(&cursor, 1, &mut || Ok(()))
            .err()
            .ok_or("revoked root disclosed next page")?
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(root.begin(None, 1, &mut || Ok(())).is_err());
    let (mut root, consent) = approved(dir.path(), BrowseLimits::default())?;
    drop(consent);
    assert!(root.begin(None, 1, &mut || Ok(())).is_err());
    let (mut root, _consent) = approved(dir.path(), BrowseLimits::default())?;
    let mut calls = 0;
    let error = root
        .begin(None, 1, &mut || {
            calls += 1;
            if calls >= 5 {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "current FileRead revoked",
                ))
            } else {
                Ok(())
            }
        })
        .err()
        .ok_or("current authorization was not checked during scanning")?;
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(calls, 5);
    Ok(())
}

#[test]
fn operation_budget_and_fixed_cursor_lifetime_are_not_reset_by_progress() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("a"), b"a")?;
    fs::write(dir.path().join("b"), b"b")?;
    let limits = BrowseLimits::new(
        10,
        1024,
        Duration::from_millis(30),
        DIRECTORY_CURSOR_LIFETIME,
    )?;
    let (mut root, _consent) = approved(dir.path(), limits)?;
    let error = root
        .begin(None, 1, &mut || {
            thread::sleep(Duration::from_millis(35));
            Ok(())
        })
        .err()
        .ok_or("original operation budget was extended")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    let limits = BrowseLimits::new(
        10,
        1024,
        DIRECTORY_OPERATION_BUDGET,
        Duration::from_millis(50),
    )?;
    let (mut root, _consent) = approved(dir.path(), limits)?;
    let cursor = root
        .begin(None, 1, &mut || Ok(()))?
        .next
        .ok_or("missing cursor")?;
    thread::sleep(Duration::from_millis(60));
    assert_eq!(
        root.next(&cursor, 1, &mut || Ok(()))
            .err()
            .ok_or("expired cursor was renewed by another page")?
            .kind(),
        io::ErrorKind::TimedOut
    );
    Ok(())
}

#[test]
fn a_cursor_that_expires_during_metadata_rescanning_cannot_deliver_the_page() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("a"), b"a")?;
    fs::write(dir.path().join("b"), b"b")?;
    let limits = BrowseLimits::new(10, 1024, Duration::from_secs(1), Duration::from_millis(40))?;
    let (mut root, _consent) = approved(dir.path(), limits)?;
    let cursor = root
        .begin(None, 1, &mut || Ok(()))?
        .next
        .ok_or("missing cursor")?;
    let mut calls = 0;
    let error = root
        .next(&cursor, 1, &mut || {
            calls += 1;
            // Page preflight and the scan's first check were within the lifetime.
            // This callback follows the real target metadata call during rescan.
            if calls == 3 {
                thread::sleep(Duration::from_millis(80));
            }
            Ok(())
        })
        .err()
        .ok_or("cursor that expired during rescan disclosed a sensitive page")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("cursor expired"));
    assert_eq!(
        calls, 3,
        "no new platform lookup may follow the expired metadata checkpoint"
    );
    assert!(
        root.next(&cursor, 1, &mut || Ok(())).is_err(),
        "expired scan retires the snapshot"
    );
    Ok(())
}

#[test]
fn owned_worker_bounds_pending_results_and_runs_disk_callbacks_on_its_thread() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("a"), b"a")?;
    fs::write(dir.path().join("b"), b"b")?;
    let owned_calls = Arc::new(AtomicBool::new(false));
    let called = owned_calls.clone();
    let (selection, _consent) =
        BrowseSelection::new(&random_id(), dir.path(), BrowseLimits::default())?;
    let (mut worker, mut ready) = DirectoryWorker::start(selection, move || {
        if thread::current().name() == Some("nestlink-directory") {
            called.store(true, Ordering::Release);
        }
        Ok(())
    })?;
    assert_eq!(
        worker
            .begin(None, 1)
            .err()
            .ok_or("opening root did not occupy its work slot")?
            .kind(),
        io::ErrorKind::WouldBlock
    );
    wait(&mut ready)?;
    assert!(ready.try_result().is_err(), "ready reply cannot be reused");
    assert!(owned_calls.load(Ordering::Acquire));
    let mut pending = worker.begin(None, 1)?;
    assert_eq!(
        worker
            .begin(None, 1)
            .err()
            .ok_or("retained result did not occupy its work slot")?
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let first = wait(&mut pending)?;
    let mut next = worker.next(first.next.ok_or("missing worker cursor")?, 1)?;
    assert_eq!(wait(&mut next)?.entries[0].name, "b");
    stopped(&mut worker)?;
    let status = worker.monitor().status();
    assert!(status.root_opened && status.finished && status.handles_closed);
    assert!(!status.cleanup_timed_out);
    assert_eq!(status.failed_operations, 0);
    Ok(())
}

#[test]
fn revoked_local_consent_suppresses_a_completed_but_unconsumed_page() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("secret-name"), b"secret")?;
    let (selection, consent) =
        BrowseSelection::new(&random_id(), dir.path(), BrowseLimits::default())?;
    let (mut worker, mut ready) = DirectoryWorker::start(selection, || Ok(()))?;
    wait(&mut ready)?;
    let mut pending = worker.begin(None, 1)?;
    thread::sleep(Duration::from_millis(50));
    consent.revoke();
    assert_eq!(
        pending
            .try_result()
            .err()
            .ok_or("revoked completed result disclosed entries")?
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    stopped(&mut worker)?;
    Ok(())
}

#[test]
fn a_completed_reply_cannot_outlive_its_fixed_snapshot_lifetime() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("secret-name"), b"secret")?;
    let limits = BrowseLimits::new(10, 1024, Duration::from_secs(1), Duration::from_millis(100))?;
    let (selection, _consent) = BrowseSelection::new(&random_id(), dir.path(), limits)?;
    let (mut worker, mut ready) = DirectoryWorker::start(selection, || Ok(()))?;
    wait(&mut ready)?;
    let mut pending = worker.begin(None, 1)?;
    let started = Instant::now();
    while worker.monitor().status().completed_operations == 0 {
        if started.elapsed() >= Duration::from_millis(100) {
            return Err(
                "test did not obtain a completed page within its original cursor lifetime".into(),
            );
        }
        thread::sleep(Duration::from_millis(1));
    }
    // Completion is a real worker fact. The reply exists, but has not been
    // delivered; the operation budget remains valid after this delay.
    thread::sleep(Duration::from_millis(120));
    let error = pending
        .try_result()
        .err()
        .ok_or("stored page bypassed its original snapshot lifetime")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("cursor expired"));
    stopped(&mut worker)?;
    Ok(())
}

struct Gate {
    enabled: AtomicBool,
    entered: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
    calls: AtomicUsize,
    trigger: usize,
}
impl Gate {
    fn new() -> Arc<Self> {
        Self::new_at(0)
    }
    fn new_at(trigger: usize) -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            changed: Condvar::new(),
            calls: AtomicUsize::new(0),
            trigger,
        })
    }
    fn check(&self) -> io::Result<()> {
        let call = if thread::current().name() == Some("nestlink-directory") {
            self.calls.fetch_add(1, Ordering::AcqRel) + 1
        } else {
            0
        };
        if call != 0
            && self.enabled.load(Ordering::Acquire)
            && (self.trigger == 0 || self.trigger == call)
        {
            self.entered.store(true, Ordering::Release);
            let mut released = self
                .released
                .lock()
                .map_err(|_| io::Error::other("test gate poisoned"))?;
            while !*released {
                released = self
                    .changed
                    .wait(released)
                    .map_err(|_| io::Error::other("test gate poisoned"))?;
            }
        }
        Ok(())
    }
    fn wait_entered(&self) -> Result {
        let started = Instant::now();
        while !self.entered.load(Ordering::Acquire) {
            if started.elapsed() >= Duration::from_secs(2) {
                return Err("worker did not reach test blocking boundary".into());
            }
            thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    }
    fn release(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = true;
        self.changed.notify_all();
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        self.release();
    }
}
struct ReleaseGate(Arc<Gate>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}
// Production authorization checks never block. This test-only boundary models
// a provider/OS call that returns after the caller has already cancelled.
#[test]
fn dropped_ticket_cannot_replace_a_still_running_job_and_cleanup_timeout_is_sticky() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("a"), b"a")?;
    let (selection, _consent) =
        BrowseSelection::new(&random_id(), dir.path(), BrowseLimits::default())?;
    let gate = Gate::new();
    let _release_on_error = ReleaseGate(gate.clone());
    let owned = gate.clone();
    let (mut worker, mut ready) = DirectoryWorker::start(selection, move || owned.check())?;
    wait(&mut ready)?;
    gate.enabled.store(true, Ordering::Release);
    let pending = worker.begin(None, 1)?;
    gate.wait_entered()?;
    drop(pending);
    assert_eq!(
        worker
            .begin(None, 1)
            .err()
            .ok_or("cancelled future released a running work slot")?
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(worker.poll_shutdown(), DirectoryShutdown::Waiting);
    thread::sleep(Duration::from_millis(270));
    assert_eq!(worker.poll_shutdown(), DirectoryShutdown::TimedOut);
    let delayed = worker.monitor().status();
    assert!(
        delayed.root_opened
            && !delayed.handles_closed
            && !delayed.finished
            && delayed.cleanup_timed_out
    );
    gate.release();
    stopped(&mut worker)?;
    let completed = worker.monitor().status();
    assert!(completed.handles_closed && completed.finished && completed.cleanup_timed_out);
    Ok(())
}

#[test]
fn worker_drop_does_not_block_or_claim_handles_closed_before_real_teardown() -> Result {
    let dir = tempfile::tempdir()?;
    let (selection, _consent) =
        BrowseSelection::new(&random_id(), dir.path(), BrowseLimits::default())?;
    let gate = Gate::new();
    let _release_on_error = ReleaseGate(gate.clone());
    let owned = gate.clone();
    let (worker, mut ready) = DirectoryWorker::start(selection, move || owned.check())?;
    wait(&mut ready)?;
    gate.enabled.store(true, Ordering::Release);
    let _pending = worker.begin(None, 1)?;
    gate.wait_entered()?;
    let monitor = worker.monitor();
    let started = Instant::now();
    drop(worker);
    assert!(started.elapsed() < Duration::from_millis(100));
    assert!(!monitor.status().handles_closed);
    thread::sleep(Duration::from_millis(270));
    assert!(monitor.status().cleanup_timed_out);
    gate.release();
    until_finished(&monitor)?;
    assert!(monitor.status().cleanup_timed_out);
    Ok(())
}

#[test]
fn revocation_during_root_opening_records_delayed_teardown_without_claiming_an_open_root() -> Result
{
    let dir = tempfile::tempdir()?;
    let (selection, consent) =
        BrowseSelection::new(&random_id(), dir.path(), BrowseLimits::default())?;
    // The second worker authorization checkpoint follows the real ambient
    // parent open, and precedes the selected root's no-follow lookup.
    let gate = Gate::new_at(2);
    let _release_on_error = ReleaseGate(gate.clone());
    gate.enabled.store(true, Ordering::Release);
    let owned = gate.clone();
    let (mut worker, mut ready) = DirectoryWorker::start(selection, move || owned.check())?;
    gate.wait_entered()?;
    let opening = worker.monitor().status();
    assert!(!opening.root_opened && !opening.handles_closed && !opening.finished);
    consent.revoke();
    thread::sleep(Duration::from_millis(270));
    assert!(worker.monitor().status().cleanup_timed_out);
    assert_eq!(
        ready
            .try_result()
            .err()
            .ok_or("revoked root initialization was delivered")?
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    gate.release();
    stopped(&mut worker)?;
    let finished = worker.monitor().status();
    assert!(
        !finished.root_opened
            && finished.handles_closed
            && finished.finished
            && finished.cleanup_timed_out
    );
    Ok(())
}

#[test]
fn original_ticket_deadline_suppresses_a_blocked_page_without_releasing_its_work_slot() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("secret"), b"secret")?;
    let limits = BrowseLimits::new(
        10,
        1024,
        Duration::from_millis(200),
        DIRECTORY_CURSOR_LIFETIME,
    )?;
    let (selection, _consent) = BrowseSelection::new(&random_id(), dir.path(), limits)?;
    let gate = Gate::new();
    let _release_on_error = ReleaseGate(gate.clone());
    let owned = gate.clone();
    let (mut worker, mut ready) = DirectoryWorker::start(selection, move || owned.check())?;
    wait(&mut ready)?;
    gate.enabled.store(true, Ordering::Release);
    let mut pending = worker.begin(None, 1)?;
    gate.wait_entered()?;
    thread::sleep(Duration::from_millis(220));
    assert_eq!(
        pending
            .try_result()
            .err()
            .ok_or("blocked page bypassed its original deadline")?
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        worker
            .begin(None, 1)
            .err()
            .ok_or("expired ticket released its running work slot")?
            .kind(),
        io::ErrorKind::WouldBlock
    );
    gate.release();
    let started = Instant::now();
    let mut refresh = loop {
        match worker.begin(None, 1) {
            Ok(refresh) => break refresh,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if started.elapsed() >= Duration::from_secs(2) {
                    return Err("timed out operation never released the actual work slot".into());
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error.into()),
        }
    };
    assert_eq!(wait(&mut refresh)?.entries[0].name, "secret");
    stopped(&mut worker)?;
    Ok(())
}

#[test]
fn worker_session_authority_failure_is_terminal_even_if_the_callback_later_returns_ok() -> Result {
    let dir = tempfile::tempdir()?;
    fs::write(dir.path().join("a"), b"a")?;
    let (selection, _consent) =
        BrowseSelection::new(&random_id(), dir.path(), BrowseLimits::default())?;
    let authorized = Arc::new(AtomicBool::new(true));
    let current = authorized.clone();
    let (mut worker, mut ready) = DirectoryWorker::start(selection, move || {
        if current.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test session revoked",
            ))
        }
    })?;
    wait(&mut ready)?;
    let mut pending = worker.begin(None, 1)?;
    authorized.store(false, Ordering::Release);
    assert!(pending.try_result().is_err());
    authorized.store(true, Ordering::Release);
    assert!(
        worker.begin(None, 1).is_err(),
        "an old worker cannot revive when authorization returns"
    );
    stopped(&mut worker)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn fifo_and_non_utf8_entries_are_rejected_without_waiting_for_a_writer() -> Result {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let dir = tempfile::tempdir()?;
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        dir.path().join("fifo"),
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    let (mut root, _consent) = approved(dir.path(), BrowseLimits::default())?;
    let started = Instant::now();
    assert!(root.begin(None, 1, &mut || Ok(())).is_err());
    assert!(started.elapsed() < Duration::from_millis(500));
    let dir = tempfile::tempdir()?;
    fs::write(
        dir.path().join(OsString::from_vec(vec![b'a', 0xff])),
        b"invalid name",
    )?;
    let (mut root, _consent) = approved(dir.path(), BrowseLimits::default())?;
    assert!(root.begin(None, 1, &mut || Ok(())).is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn metadata_browsing_does_not_require_content_read_permission() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("attributes-only");
    fs::write(&file, b"private content")?;
    fs::set_permissions(&file, fs::Permissions::from_mode(0o0))?;
    let (mut root, _consent) = approved(dir.path(), BrowseLimits::default())?;
    let page = root.begin(None, 1, &mut || Ok(()))?;
    assert_eq!(page.entries[0].name, "attributes-only");
    assert_eq!(page.entries[0].size, Some(15));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn descendant_mounts_cannot_cross_the_selected_root_filesystem() -> Result {
    use std::os::unix::fs::MetadataExt;
    assert_ne!(
        fs::metadata("/")?.dev(),
        fs::metadata("/proc")?.dev(),
        "test requires the existing proc filesystem"
    );
    let (mut root, _consent) = approved(Path::new("/"), BrowseLimits::default())?;
    assert_eq!(
        root.begin(Some("proc"), 1, &mut || Ok(()))
            .err()
            .ok_or("descendant filesystem was traversed")?
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    Ok(())
}
