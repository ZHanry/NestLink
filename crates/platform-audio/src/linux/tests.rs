use super::*;

fn shared() -> io::Result<Arc<Shared>> {
    Ok(Arc::new(Shared::new(Box::new(|| true))?))
}
fn chunk(value: i16) -> CapturedAudio {
    CapturedAudio {
        captured_at: Instant::now(),
        chunk: AudioChunk {
            source: 7,
            channels: 2,
            pts_48khz: 0,
            samples: vec![value; CHUNK_FRAMES * 2],
        },
    }
}
#[test]
fn worker_progress_and_cleanup_deadlines_never_restart() -> io::Result<()> {
    let state = shared()?;
    state.lock()?.heartbeat = Instant::now() - HEARTBEAT * 2;
    assert!(state.control(true, 1).is_err());
    assert!(!state.lock()?.ready);
    assert!(state.check().is_err());
    state.lock()?.heartbeat = Instant::now();
    assert_eq!(state.control(true, 1)?, 2);
    let clean = shared()?;
    let mut device = Device {
        shared: clean.clone(),
        worker: None,
        cleanup_until: Some(Instant::now()),
    };
    assert_eq!(
        device.reset().err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    clean.complete(Ok(()), Ok(()));
    assert_eq!(
        device.reset().err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    Ok(())
}
#[test]
fn bounded_playback_discards_old_audio_and_stop_clears_partial_chunk() -> io::Result<()> {
    let state = shared()?;
    let binding = AudioBinding {
        source: 7,
        channels: 2,
        connection: 1,
    };
    let mut device = LinuxAudioPlayback {
        device: Device {
            shared: state.clone(),
            worker: None,
            cleanup_until: Some(Instant::now()),
        },
        binding,
    };
    assert!(!state.armed.load(Ordering::SeqCst));
    let mut invalid = chunk(1).chunk;
    invalid.source = 9;
    assert!(device.enqueue(&invalid).is_err());
    assert!(!state.armed.load(Ordering::SeqCst));
    for value in 1..=8 {
        device.enqueue(&chunk(value).chunk)?;
    }
    assert_eq!(state.lock()?.queue.len(), 1);
    let mut output = [0; 100];
    state.fill(&mut output, 2)?;
    assert!(output.iter().all(|v| *v == 8));
    assert!(state.lock()?.playing.is_some());
    state.stop();
    assert!(state.lock()?.queue.is_empty());
    assert!(state.lock()?.playing.is_none());
    assert!(state.fill(&mut output, 2).is_err());
    assert!(device.enqueue(&chunk(9).chunk).is_err());
    Ok(())
}
#[test]
fn local_session_loss_and_callback_panic_keep_the_first_failure() -> io::Result<()> {
    let active = Arc::new(AtomicBool::new(true));
    let observed = active.clone();
    let state = Arc::new(Shared::new(Box::new(move || {
        observed.load(Ordering::SeqCst)
    }))?);
    state.captured(vec![chunk(4)])?;
    active.store(false, Ordering::SeqCst);
    assert!(state.check().is_err());
    active.store(true, Ordering::SeqCst);
    assert!(state.captured(vec![chunk(5)]).is_err());
    assert!(state.lock()?.queue.is_empty());
    let original = state
        .lock()?
        .failure
        .as_ref()
        .map(|error| error.message.clone());
    state.fail(io::Error::other("late cleanup"));
    assert_eq!(
        original,
        state
            .lock()?
            .failure
            .as_ref()
            .map(|error| error.message.clone())
    );
    let panic_state = shared()?;
    assert_eq!(
        guarded(&panic_state, || panic!("owned callback panic")),
        -libc::EIO
    );
    assert!(panic_state.check().is_err());
    Ok(())
}
