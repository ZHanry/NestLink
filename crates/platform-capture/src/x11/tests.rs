use super::*;
use nestlink_remote::input::InputLayout;
use std::sync::atomic::AtomicUsize;

fn display(source: u32, left: i32) -> Display {
    Display {
        source,
        logical: InputLayout {
            left,
            top: 0,
            width: 2,
            height: 2,
        },
    }
}
fn frame(source: u32) -> RawFrame {
    RawFrame {
        source,
        width: 2,
        height: 2,
        captured_at: Instant::now(),
        pixels: vec![source as u8; 16],
    }
}
#[derive(Default)]
struct Facts {
    alive: AtomicBool,
    captures: AtomicUsize,
    closes: AtomicUsize,
    fault: AtomicUsize,
    calls: Mutex<Vec<Instant>>,
    owner: Mutex<Option<thread::ThreadId>>,
    closed_on: Mutex<Option<thread::ThreadId>>,
}
struct Gate {
    at: usize,
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}
fn gate(at: usize) -> (Gate, mpsc::Receiver<()>, mpsc::SyncSender<()>) {
    let (entered, received) = mpsc::sync_channel(1);
    let (released, release) = mpsc::sync_channel(1);
    (
        Gate {
            at,
            entered,
            release,
        },
        received,
        released,
    )
}
struct FakeSource {
    displays: Vec<Display>,
    facts: Arc<Facts>,
    capture_gate: Option<Gate>,
    close_gate: Option<Gate>,
}
fn fake() -> (FakeSource, Arc<Facts>) {
    let facts = Arc::new(Facts::default());
    facts.alive.store(true, Ordering::SeqCst);
    (
        FakeSource {
            displays: vec![display(11, -2), display(42, 0)],
            facts: facts.clone(),
            capture_gate: None,
            close_gate: None,
        },
        facts,
    )
}
impl FakeSource {
    fn record(&self, until: Instant) -> io::Result<()> {
        self.facts
            .calls
            .lock()
            .map_err(|_| io::Error::other("fixture calls poisoned"))?
            .push(until);
        let mut owner = self
            .facts
            .owner
            .lock()
            .map_err(|_| io::Error::other("fixture owner poisoned"))?;
        let current = thread::current().id();
        if owner.is_some_and(|thread| thread != current) {
            return Err(io::Error::other(
                "fixture source used from different threads",
            ));
        }
        *owner = Some(current);
        Ok(())
    }
}
impl Source for FakeSource {
    fn displays(&self) -> &[Display] {
        &self.displays
    }
    fn active(&self) -> Box<dyn Fn() -> bool + Send + Sync> {
        let facts = self.facts.clone();
        Box::new(move || facts.alive.load(Ordering::SeqCst))
    }
    fn check_until(&mut self, until: Instant) -> io::Result<()> {
        self.record(until)?;
        if self.facts.fault.load(Ordering::SeqCst) == 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture desktop changed",
            ));
        }
        Ok(())
    }
    fn capture_until(&mut self, source: u32, until: Instant) -> io::Result<RawFrame> {
        self.record(until)?;
        let count = self.facts.captures.fetch_add(1, Ordering::SeqCst) + 1;
        if self
            .capture_gate
            .as_ref()
            .is_some_and(|gate| gate.at == count)
        {
            let gate = self
                .capture_gate
                .take()
                .ok_or_else(|| io::Error::other("fixture gate disappeared"))?;
            gate.entered.send(()).map_err(io::Error::other)?;
            gate.release
                .recv_timeout(Duration::from_secs(2))
                .map_err(io::Error::other)?;
        }
        match self.facts.fault.load(Ordering::SeqCst) {
            2 => panic!("deliberate private capture fixture panic"),
            3 => Ok(RawFrame {
                source,
                width: 1,
                height: 2,
                captured_at: Instant::now(),
                pixels: vec![0; 8],
            }),
            4 => Ok(frame(source + 1)),
            _ => Ok(frame(source)),
        }
    }
    fn close(&mut self) -> io::Result<()> {
        self.facts.alive.store(false, Ordering::SeqCst);
        self.facts.closes.fetch_add(1, Ordering::SeqCst);
        *self
            .facts
            .closed_on
            .lock()
            .map_err(|_| io::Error::other("fixture close thread poisoned"))? =
            Some(thread::current().id());
        if let Some(gate) = self.close_gate.take() {
            gate.entered.send(()).map_err(io::Error::other)?;
            gate.release
                .recv_timeout(Duration::from_secs(2))
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
}
fn next_frame(capture: &mut X11Capture) -> io::Result<RawFrame> {
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(frame) = capture.poll_frame()? {
            return Ok(frame);
        }
        if Instant::now() >= until {
            return Err(timeout("fixture did not produce its frame"));
        }
        thread::sleep(Duration::from_millis(2));
    }
}
fn ended(capture: &X11Capture) -> io::Result<()> {
    let until = Instant::now() + Duration::from_secs(1);
    let mut state = capture
        .shared
        .state
        .lock()
        .map_err(|_| io::Error::other("fixture state poisoned"))?;
    while state.ended.is_none() {
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timeout("fixture worker did not finish"));
        }
        state = capture
            .shared
            .wake
            .wait_timeout(state, remaining)
            .map_err(|_| io::Error::other("fixture ended wait poisoned"))?
            .0;
    }
    Ok(())
}

#[test]
fn selected_sources_round_deadlines_and_worker_owned_cleanup() -> io::Result<()> {
    for selected in [vec![], vec![11, 11], vec![7]] {
        let (source, facts) = fake();
        assert!(X11Capture::start(source, selected).is_err());
        assert_eq!(facts.captures.load(Ordering::SeqCst), 0);
    }
    let (source, facts) = fake();
    let mut capture = X11Capture::start(source, vec![42, 11])?;
    let first = next_frame(&mut capture)?;
    let second = next_frame(&mut capture)?;
    assert_eq!((first.source, second.source), (42, 11));
    assert_eq!(
        capture
            .displays()
            .iter()
            .map(|d| d.source)
            .collect::<Vec<_>>(),
        vec![42, 11]
    );
    thread::sleep(Duration::from_millis(80));
    {
        let state = capture
            .shared
            .state
            .lock()
            .map_err(|_| io::Error::other("state poisoned"))?;
        assert_eq!(state.frames.len(), 2);
        assert_eq!(state.bytes, 32);
    }
    capture.reset()?;
    capture.reset()?;
    assert!(capture.poll_frame().is_err());
    assert_eq!(facts.closes.load(Ordering::SeqCst), 1);
    let owner = *facts
        .owner
        .lock()
        .map_err(|_| io::Error::other("owner poisoned"))?;
    assert_ne!(owner, Some(thread::current().id()));
    assert_eq!(
        *facts
            .closed_on
            .lock()
            .map_err(|_| io::Error::other("close poisoned"))?,
        owner
    );
    let calls = facts
        .calls
        .lock()
        .map_err(|_| io::Error::other("calls poisoned"))?;
    for round in calls[1..].chunks_exact(4) {
        assert!(round.iter().all(|deadline| *deadline == round[0]));
    }
    Ok(())
}

#[test]
fn late_frame_without_consumer_poll_never_refreshes_or_publishes() -> io::Result<()> {
    let (mut source, facts) = fake();
    let (gate, entered, release) = gate(1);
    source.capture_gate = Some(gate);
    let mut capture = X11Capture::start(source, vec![11])?;
    entered
        .recv_timeout(Duration::from_secs(1))
        .map_err(io::Error::other)?;
    // No check/poll call assists the worker in detecting this expired round.
    thread::sleep(ROUND + Duration::from_millis(30));
    release.send(()).map_err(io::Error::other)?;
    ended(&capture)?;
    assert!(capture.poll_frame().is_err());
    assert!(
        capture
            .shared
            .state
            .lock()
            .map_err(|_| io::Error::other("state poisoned"))?
            .frames
            .is_empty()
    );
    assert_eq!(facts.closes.load(Ordering::SeqCst), 1);
    assert_eq!(
        capture.reset().err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}

#[test]
fn reset_uses_one_deadline_and_discards_an_inflight_frame() -> io::Result<()> {
    let (mut source, facts) = fake();
    let (gate, entered, release) = gate(2);
    source.capture_gate = Some(gate);
    let mut capture = X11Capture::start(source, vec![11])?;
    entered
        .recv_timeout(Duration::from_secs(1))
        .map_err(io::Error::other)?;
    assert!(
        !capture
            .shared
            .state
            .lock()
            .map_err(|_| io::Error::other("state poisoned"))?
            .frames
            .is_empty()
    );
    let started = Instant::now();
    assert_eq!(
        capture.reset().err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    let repeated = Instant::now();
    assert_eq!(
        capture.reset().err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(repeated.elapsed() < Duration::from_millis(100));
    assert!(
        capture
            .shared
            .state
            .lock()
            .map_err(|_| io::Error::other("state poisoned"))?
            .frames
            .is_empty()
    );
    release.send(()).map_err(io::Error::other)?;
    ended(&capture)?;
    capture.reset()?;
    assert_eq!(facts.closes.load(Ordering::SeqCst), 1);
    assert!(capture.poll_frame().is_err());
    Ok(())
}

#[test]
fn old_heartbeat_cannot_be_revived_by_late_facts_or_pixels() -> io::Result<()> {
    let shared = Shared::new(BTreeSet::from([11]), Box::new(|| true));
    shared.publish(vec![frame(11)], Instant::now() + ROUND)?;
    shared
        .state
        .lock()
        .map_err(|_| io::Error::other("state poisoned"))?
        .checked = Instant::now() - HEARTBEAT - Duration::from_millis(1);
    assert_eq!(
        shared
            .refresh(Instant::now() + ROUND)
            .err()
            .map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(
        shared
            .publish(vec![frame(11)], Instant::now() + ROUND)
            .is_err()
    );
    assert!(shared.take().is_err());
    assert!(
        shared
            .state
            .lock()
            .map_err(|_| io::Error::other("state poisoned"))?
            .frames
            .is_empty()
    );
    Ok(())
}

#[test]
fn asynchronous_authority_loss_denies_queued_delivery_while_source_is_blocked() -> io::Result<()> {
    let (source, facts) = fake();
    facts.alive.store(false, Ordering::SeqCst);
    assert!(X11Capture::start(source, vec![11]).is_err());
    assert_eq!(facts.captures.load(Ordering::SeqCst), 0);

    let (mut source, facts) = fake();
    let (gate, entered, release) = gate(2);
    source.capture_gate = Some(gate);
    let mut capture = X11Capture::start(source, vec![11])?;
    entered
        .recv_timeout(Duration::from_secs(1))
        .map_err(io::Error::other)?;
    assert!(
        !capture
            .shared
            .state
            .lock()
            .map_err(|_| io::Error::other("state poisoned"))?
            .frames
            .is_empty()
    );
    facts.alive.store(false, Ordering::SeqCst);
    // The native source is still inside its blocked capture call. A consumer
    // must observe asynchronous logind revocation before that call completes.
    assert_eq!(
        capture.poll_frame().err().map(|e| e.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert!(
        capture
            .shared
            .state
            .lock()
            .map_err(|_| io::Error::other("state poisoned"))?
            .frames
            .is_empty()
    );
    facts.alive.store(true, Ordering::SeqCst);
    assert!(capture.check().is_err()); // loss is latched; old authority cannot resume
    release.send(()).map_err(io::Error::other)?;
    ended(&capture)?;
    capture.reset()?;
    assert_eq!(facts.closes.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn platform_fault_panic_or_changed_pixels_revoke_before_source_cleanup() -> io::Result<()> {
    for fault in 1..=4 {
        let (mut source, facts) = fake();
        let (gate, closing, release) = gate(1);
        source.close_gate = Some(gate);
        let mut capture = X11Capture::start(source, vec![11])?;
        let _ = next_frame(&mut capture)?;
        facts.fault.store(fault, Ordering::SeqCst);
        closing
            .recv_timeout(Duration::from_secs(1))
            .map_err(io::Error::other)?;
        assert!(capture.shared.stopped.load(Ordering::SeqCst));
        assert!(
            capture
                .shared
                .state
                .lock()
                .map_err(|_| io::Error::other("state poisoned"))?
                .frames
                .is_empty()
        );
        assert!(capture.poll_frame().is_err());
        release.send(()).map_err(io::Error::other)?;
        ended(&capture)?;
        assert!(capture.reset().is_err());
        assert_eq!(facts.closes.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[test]
fn future_foreign_missing_and_geometry_changed_rounds_are_rejected() -> io::Result<()> {
    let multiple = Shared::new(BTreeSet::from([11, 42]), Box::new(|| true));
    multiple.publish(vec![frame(11), frame(42)], Instant::now() + ROUND)?;
    assert_eq!(multiple.take()?.map(|frame| frame.source), Some(11));
    multiple.publish(vec![frame(11), frame(42)], Instant::now() + ROUND)?;
    assert_eq!(multiple.take()?.map(|frame| frame.source), Some(42));
    let shared = Shared::new(BTreeSet::from([11]), Box::new(|| true));
    assert!(
        shared
            .publish(vec![frame(42)], Instant::now() + ROUND)
            .is_err()
    );
    assert!(shared.publish(vec![], Instant::now() + ROUND).is_err());
    let mut future = frame(11);
    future.captured_at = Instant::now() + Duration::from_secs(1);
    assert!(
        shared
            .publish(vec![future], Instant::now() + ROUND)
            .is_err()
    );
    shared.publish(vec![frame(11)], Instant::now() + ROUND)?;
    let mut changed = frame(11);
    changed.width = 1;
    changed.pixels.truncate(8);
    assert!(
        shared
            .publish(vec![changed], Instant::now() + ROUND)
            .is_err()
    );
    assert!(
        shared
            .publish(vec![frame(11)], Instant::now() - Duration::from_millis(1))
            .is_err()
    );
    assert!(shared.take().is_err());
    Ok(())
}
