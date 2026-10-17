use super::*;
unsafe extern "C" {
    fn nl_audio_copy_samples(
        input: *const i16,
        frames: u32,
        channels: u32,
        flags: u32,
        out: *mut i16,
        capacity: usize,
    ) -> i32;
    fn nl_audio_notice_probe(event: u32) -> i32;
}
fn chunk(pts: u64) -> CapturedAudio {
    CapturedAudio {
        captured_at: Instant::now(),
        chunk: AudioChunk {
            source: 4,
            channels: 2,
            pts_48khz: pts,
            samples: vec![7; CHUNK_FRAMES * 2],
        },
    }
}
#[test]
fn native_packet_copy_handles_silence_and_rejects_bad_flags_and_budgets() {
    let input = [17i16; MAX_PACKET_FRAMES * 2];
    let mut output = [8i16; MAX_PACKET_FRAMES * 2 + 1];
    // SAFETY: owned fixed corpus, explicit capacity. Rejected cases must not write.
    unsafe {
        assert_eq!(
            nl_audio_copy_samples(input.as_ptr(), 1920, 2, 0, output.as_mut_ptr(), 3840),
            0
        );
        assert!(output[..3840].iter().all(|v| *v == 17));
        assert_eq!(output[3840], 8);
        assert_eq!(
            nl_audio_copy_samples(std::ptr::null(), 960, 2, 2, output.as_mut_ptr(), 1920),
            0
        );
        assert!(output[..1920].iter().all(|v| *v == 0));
        assert_eq!(output[1920], 17);
        for (frames, channels, flags, capacity) in [
            (0, 2, 0, 3840),
            (1921, 2, 0, 3840),
            (960, 3, 0, 3840),
            (960, 2, 4, 3840),
            (960, 2, 8, 3840),
            (960, 2, 0, 1919),
        ] {
            output.fill(19);
            assert!(
                nl_audio_copy_samples(
                    input.as_ptr(),
                    frames,
                    channels,
                    flags,
                    output.as_mut_ptr(),
                    capacity
                ) < 0
            );
            assert!(output.iter().all(|v| *v == 19));
        }
        assert!(nl_audio_copy_samples(std::ptr::null(), 960, 2, 0, output.as_mut_ptr(), 1920) < 0);
    }
}
#[test]
fn endpoint_notifications_are_sticky_and_do_not_follow_os_default() {
    // SAFETY: production callbacks run only against their own synthetic stack object.
    unsafe {
        assert_eq!(nl_audio_notice_probe(0), 0);
        assert_eq!(nl_audio_notice_probe(1), 0);
        for event in [2, 3, 4] {
            assert_eq!(nl_audio_notice_probe(event), 1);
        }
        assert_eq!(nl_audio_notice_probe(5), 0);
    }
}
#[test]
fn playback_queue_drops_old_pcm_and_invalidation_prevents_delivery() -> io::Result<()> {
    let shared = Shared::new();
    assert!(!shared.armed.load(Ordering::SeqCst));
    for pts in [0, 960, 1920] {
        shared.publish(chunk(pts), PLAYBACK_QUEUED)?;
    }
    assert_eq!(shared.lock()?.queue.len(), 2);
    assert_eq!(shared.pop()?.map(|v| v.chunk.pts_48khz), Some(960));
    shared
        .lock()?
        .queue
        .front_mut()
        .ok_or_else(|| io::Error::other("fixture queue empty"))?
        .captured_at = Instant::now() - CAPTURE_AGE - TICK;
    assert!(shared.pop()?.is_none());
    shared.publish(chunk(2880), PLAYBACK_QUEUED)?;
    shared.invalidated.store(true, Ordering::SeqCst);
    assert!(shared.pop().is_err());
    assert!(shared.publish(chunk(3840), PLAYBACK_QUEUED).is_err());
    shared.stop();
    assert!(shared.lock()?.queue.is_empty());
    Ok(())
}
#[test]
fn worker_stall_and_late_completion_keep_cleanup_timeout() -> io::Result<()> {
    let shared = Arc::new(Shared::new());
    let work = shared.clone();
    let (release, wait) = mpsc::channel();
    let worker = thread::spawn(move || {
        let _ = wait.recv();
        work.finish(Ok(()));
    });
    let mut device = Device {
        shared,
        binding: AudioBinding {
            connection: 1,
            source: 4,
            channels: 2,
        },
        worker: Some(worker),
        cleanup_deadline: None,
        cleanup_failure: None,
    };
    let start = Instant::now();
    assert_eq!(
        device.reset().err().map(|v| v.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    release.send(()).map_err(io::Error::other)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    while !device.shared.lock()?.ended {
        if Instant::now() > deadline {
            return Err(io::Error::other("fixture worker stuck"));
        }
        thread::sleep(TICK);
    }
    assert_eq!(
        device.reset().err().map(|v| v.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(device.check().is_err());
    Ok(())
}
#[test]
fn cleanup_error_and_heartbeat_loss_remain_terminal() -> io::Result<()> {
    let shared = Arc::new(Shared::new());
    let mut device = Device {
        shared: shared.clone(),
        binding: AudioBinding {
            connection: 1,
            source: 4,
            channels: 2,
        },
        worker: None,
        cleanup_deadline: None,
        cleanup_failure: None,
    };
    shared.publish(chunk(0), CAPTURE_QUEUED)?;
    shared.lock()?.heartbeat = Instant::now() - HEARTBEAT - TICK;
    assert!(device.check().is_err());
    shared.lock()?.heartbeat = Instant::now();
    assert!(device.check().is_err());
    assert!(shared.lock()?.queue.is_empty());
    shared.record_cleanup(Err(io::Error::new(
        io::ErrorKind::NotConnected,
        "synthetic HRESULT 0x88890004",
    )));
    shared.record_cleanup(Ok(()));
    shared.record_cleanup(Err(io::Error::other("later observer cleanup failure")));
    shared.finish(Err(io::Error::other("synthetic worker failure")));
    assert_eq!(
        device.reset().err().map(|v| v.kind()),
        Some(io::ErrorKind::NotConnected)
    );
    assert!(
        device
            .reset()
            .err()
            .is_some_and(|v| v.to_string().contains("0x88890004"))
    );
    Ok(())
}

#[test]
fn unarmed_worker_does_not_start_and_cancel_during_start_prevents_any_read() -> io::Result<()> {
    use std::sync::atomic::AtomicUsize;
    struct Stalled {
        checked: mpsc::SyncSender<()>,
        started: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
        reads: Arc<AtomicUsize>,
    }
    impl Backend for Stalled {
        fn check(&self) -> io::Result<()> {
            let _ = self.checked.try_send(());
            Ok(())
        }
        fn start(&self) -> io::Result<()> {
            self.started.send(()).map_err(io::Error::other)?;
            self.release
                .recv_timeout(Duration::from_secs(2))
                .map_err(io::Error::other)
        }
        fn capture(&self, _: &mut [i16]) -> io::Result<(usize, u64, Duration, bool)> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok((0, 0, Duration::ZERO, false))
        }
        fn write(&self, _: &[i16], _: u8) -> io::Result<usize> {
            Err(io::Error::other("capture fixture must not write"))
        }
    }
    let shared = Arc::new(Shared::new());
    let reads = Arc::new(AtomicUsize::new(0));
    let (checked, check_wait) = mpsc::sync_channel(1);
    let (started, start_wait) = mpsc::sync_channel(1);
    let (release, release_wait) = mpsc::channel();
    let backend = Stalled {
        checked,
        started,
        release: release_wait,
        reads: reads.clone(),
    };
    let work = shared.clone();
    let worker = thread::spawn(move || {
        drive(
            &work,
            AudioBinding {
                connection: 1,
                source: 4,
                channels: 2,
            },
            true,
            &backend,
            || Ok(()),
        )
    });
    check_wait
        .recv_timeout(Duration::from_secs(1))
        .map_err(io::Error::other)?;
    assert!(matches!(
        start_wait.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    shared.armed.store(true, Ordering::SeqCst);
    shared.wake.notify_all();
    start_wait
        .recv_timeout(Duration::from_secs(1))
        .map_err(io::Error::other)?;
    shared.stop();
    release.send(()).map_err(io::Error::other)?;
    worker
        .join()
        .map_err(|_| io::Error::other("fixture worker panicked"))??;
    assert_eq!(
        reads.load(Ordering::SeqCst),
        0,
        "cancelled Start must not begin a later sample read"
    );
    Ok(())
}
#[test]
#[ignore = "requires real interactive Windows audio services; initialization only, no Start, capture or speaker writes"]
fn actual_selected_endpoints_initialize_without_starting_audio() -> io::Result<()> {
    let endpoints = WindowsAudioEndpoint::enumerate()?;
    if endpoints.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no active render endpoints",
        ));
    }
    println!("active render endpoints: {}", endpoints.len());
    for endpoint in endpoints {
        for channels in [1, 2] {
            let binding = AudioBinding {
                connection: 1,
                source: 4,
                channels,
            };
            // Native workers initialize without arming; no user sound is read or emitted.
            let mut capture = WindowsAudioCapture::open(endpoint.clone(), binding)?;
            let mut playback = WindowsAudioPlayback::open(endpoint.clone(), binding)?;
            assert!(!capture.0.shared.armed.load(Ordering::SeqCst));
            assert!(!playback.0.shared.armed.load(Ordering::SeqCst));
            capture.check()?;
            playback.check()?;
            capture.reset()?;
            playback.reset()?;
            println!(
                "endpoint {}: channels={} initialized and reset",
                endpoint.name(),
                channels
            );
        }
    }
    Ok(())
}
