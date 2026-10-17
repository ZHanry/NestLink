use super::*;

fn display() -> Display {
    Display {
        source: 1,
        logical: InputLayout {
            left: 0,
            top: 0,
            width: 12,
            height: 8,
        },
    }
}
fn frame(source: u32) -> RawFrame {
    RawFrame {
        source,
        width: 12,
        height: 8,
        captured_at: Instant::now(),
        pixels: vec![0; 12 * 8 * 4],
    }
}

#[test]
fn terminal_queue_replaces_owned_frames_and_rejects_stale_worker() -> io::Result<()> {
    let shared = Shared::new();
    shared.publish(frame(1))?;
    shared.publish(frame(1))?;
    shared.publish(frame(2))?;
    {
        let state = shared
            .state
            .lock()
            .map_err(|_| io::Error::other("state poisoned"))?;
        assert_eq!(state.frames.len(), 2);
        assert_eq!(state.bytes, 12 * 8 * 4 * 2);
    }
    shared.invalidated.store(true, Ordering::SeqCst);
    assert!(shared.publish(frame(1)).is_err());
    assert!(shared.check().is_err());
    shared.stop();
    let state = shared
        .state
        .lock()
        .map_err(|_| io::Error::other("state poisoned"))?;
    assert!(state.frames.is_empty());
    assert_eq!(state.bytes, 0);
    assert!(frame_bytes(8192, 8192).is_err());
    assert!(frame_bytes(u32::MAX, 2).is_err());
    assert!(frame_bytes(u32::MAX, u32::MAX).is_err());
    assert_eq!(frame_bytes(1920, 1080)?, 1920 * 1080 * 4);
    Ok(())
}

#[test]
fn stalled_worker_cleanup_has_one_deadline_and_cannot_publish_after_stop() -> io::Result<()> {
    let shared = Arc::new(Shared::new());
    let worker_shared = shared.clone();
    let (release, wait) = mpsc::channel();
    let worker = thread::spawn(move || {
        let _ = wait.recv();
        assert!(worker_shared.publish(frame(1)).is_err());
        worker_shared.finish(Ok(()));
    });
    let mut capture = WindowsCapture {
        shared,
        displays: vec![display()],
        worker: Some(worker),
        cleanup_deadline: None,
    };
    let started = Instant::now();
    assert_eq!(
        capture.reset().err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    let retry = Instant::now();
    assert_eq!(
        capture.reset().err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert!(retry.elapsed() < Duration::from_millis(100));
    assert!(capture.poll_frame().is_err());
    release.send(()).map_err(io::Error::other)?;
    let deadline = Instant::now() + Duration::from_secs(1);
    while capture
        .worker
        .as_ref()
        .is_some_and(|worker| !worker.is_finished())
    {
        if Instant::now() >= deadline {
            return Err(io::Error::other("fixture worker did not finish"));
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        capture.reset().err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut),
        "late worker completion cannot erase the original cleanup timeout"
    );
    let shared = Arc::new(Shared::new());
    let earlier = Instant::now() - CLEANUP;
    shared.finish(Ok(()));
    let mut raced = WindowsCapture {
        shared,
        displays: vec![display()],
        worker: None,
        cleanup_deadline: Some(earlier),
    };
    assert_eq!(
        raced.reset().err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut),
        "late completion before waiter reacquires the state must still time out"
    );
    Ok(())
}

#[test]
fn missed_heartbeat_is_terminal_before_delivery() -> io::Result<()> {
    let shared = Arc::new(Shared::new());
    shared.publish(frame(1))?;
    shared
        .state
        .lock()
        .map_err(|_| io::Error::other("state poisoned"))?
        .checked = Instant::now() - HEARTBEAT - Duration::from_millis(1);
    let mut capture = WindowsCapture {
        shared: shared.clone(),
        displays: vec![display()],
        worker: None,
        cleanup_deadline: None,
    };
    assert!(capture.poll_frame().is_err());
    shared.checked()?;
    assert!(capture.check().is_err());
    shared.finish(Ok(()));
    capture.reset()?;
    Ok(())
}

fn synthetic_cursor(monochrome: bool) -> io::Result<OwnedIcon> {
    let mut owned = IconBitmaps(ICONINFO {
        fIcon: 0,
        xHotspot: 2,
        yHotspot: 1,
        ..ICONINFO::default()
    });
    if monochrome {
        // Four rows of AND mask, followed by four XOR rows. First pixel is
        // white, second is transparent, third inverts, fourth is black.
        let mask = [
            0x60u8, 0, 0xf0, 0, 0xf0, 0, 0xf0, 0, 0xa0, 0, 0, 0, 0, 0, 0, 0,
        ];
        // SAFETY: 4x8 one-bit DDB with documented word-aligned rows; CreateBitmap copies.
        owned.0.hbmMask = unsafe { CreateBitmap(4, 8, 1, 1, mask.as_ptr().cast()) };
    } else {
        let mask = [0u8; 8];
        // SAFETY: 4x4 one-bit DDB with word-aligned rows, initialized mask.
        owned.0.hbmMask = unsafe { CreateBitmap(4, 4, 1, 1, mask.as_ptr().cast()) };
        let info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: 4,
                biHeight: -4,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                biSizeImage: 64,
                ..BITMAPINFOHEADER::default()
            },
            ..BITMAPINFO::default()
        };
        let mut bits = null_mut();
        // SAFETY: private unselected DIB; CreateIconIndirect may select/copy it.
        owned.0.hbmColor = unsafe {
            CreateDIBSection(null_mut(), &info, DIB_RGB_COLORS, &mut bits, null_mut(), 0)
        };
        if owned.0.hbmColor.is_null() || bits.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut pixels = [0u8; 64];
        pixels[0..4].copy_from_slice(&[255, 255, 255, 255]);
        pixels[20..24].copy_from_slice(&[0, 255, 255, 255]);
        pixels[40..44].copy_from_slice(&[255, 0, 0, 128]);
        pixels[60..64].copy_from_slice(&[0, 255, 0, 255]);
        // SAFETY: exact writable DIB allocation, no pending/concurrent GDI use.
        unsafe { std::ptr::copy_nonoverlapping(pixels.as_ptr(), bits.cast(), pixels.len()) };
    }
    if owned.0.hbmMask.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: valid owned bitmaps not selected into any DC; Windows copies them.
    let cursor = unsafe { CreateIconIndirect(&owned.0) };
    if cursor.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedIcon(cursor))
}
fn fill_surface(surface: &Surface, color: [u8; 4]) -> io::Result<()> {
    // SAFETY: finish all native draws before CPU writes to this owned DIB.
    if unsafe { GdiFlush() } == 0 {
        return Err(io::Error::last_os_error());
    }
    let pixels = unsafe { std::slice::from_raw_parts_mut(surface.bits, surface.bytes) };
    for pixel in pixels.chunks_exact_mut(4) {
        pixel.copy_from_slice(&color);
    }
    Ok(())
}

#[test]
fn private_cursor_pixels_preserve_hotspot_negative_origin_clipping_and_transparency()
-> io::Result<()> {
    let surface = Surface::new(Display {
        source: 1,
        logical: InputLayout {
            left: -1920,
            top: -200,
            width: 12,
            height: 8,
        },
    })?;
    let background = [40, 80, 120, 255];
    let original = synthetic_cursor(false)?;
    let mut cursor = CursorImage::copy(original.0, [-1916, -197])?;
    drop(original); // the rendering handle must be an independent copy
    assert_eq!(
        (cursor.width, cursor.height, cursor.hotspot),
        (4, 4, [2, 1])
    );
    fill_surface(&surface, background)?;
    cursor.draw(&surface)?;
    let first = surface.read(Instant::now())?;
    let pixel = |frame: &RawFrame, x: usize, y: usize| -> [u8; 4] {
        let start = (y * frame.width as usize + x) * 4;
        [
            frame.pixels[start],
            frame.pixels[start + 1],
            frame.pixels[start + 2],
            frame.pixels[start + 3],
        ]
    };
    assert_eq!(pixel(&first, 2, 2), [255, 255, 255, 255]);
    assert_eq!(pixel(&first, 3, 3), [0, 255, 255, 255]);
    assert_eq!(pixel(&first, 3, 2), background); // fully transparent cursor pixel
    let blended = pixel(&first, 4, 4);
    assert!((147..=148).contains(&blended[0]), "{blended:?}");
    assert!((39..=40).contains(&blended[1]));
    assert!((59..=60).contains(&blended[2]));
    assert_eq!(blended[3], 255);
    assert_eq!(pixel(&first, 5, 5), [0, 255, 0, 255]);

    // Hotspot outside the monitor still leaves the cursor's last column visible.
    cursor.position = [-1921, -199];
    fill_surface(&surface, background)?;
    cursor.draw(&surface)?;
    let clipped = surface.read(Instant::now())?;
    assert_eq!(pixel(&clipped, 0, 3), [0, 255, 0, 255]);
    assert_eq!(pixel(&clipped, 1, 3), background);

    // Extreme external positions must be skipped without i32 subtraction overflow.
    for position in [[i32::MIN, i32::MIN], [i32::MAX, i32::MAX], [-1906, -190]] {
        cursor.position = position;
        fill_surface(&surface, background)?;
        cursor.draw(&surface)?;
        assert!(
            surface
                .read(Instant::now())?
                .pixels
                .chunks_exact(4)
                .all(|p| p == background)
        );
    }

    let original = synthetic_cursor(true)?;
    let mono = CursorImage::copy(original.0, [-1918, -199])?;
    fill_surface(&surface, background)?;
    mono.draw(&surface)?;
    let masked = surface.read(Instant::now())?;
    assert_eq!(pixel(&masked, 0, 0), [255, 255, 255, 255]);
    assert_eq!(pixel(&masked, 1, 0), background);
    assert_eq!(pixel(&masked, 2, 0), [215, 175, 135, 255]);
    assert_eq!(pixel(&masked, 3, 0), [0, 0, 0, 255]);
    assert!(!cursor_visible(0)?);
    assert!(cursor_visible(CURSOR_SHOWING)?);
    assert!(!cursor_visible(CURSOR_SUPPRESSED)?);
    assert!(!cursor_visible(CURSOR_SHOWING | CURSOR_SUPPRESSED)?);
    assert!(cursor_visible(4).is_err());
    Ok(())
}

unsafe extern "system" fn fixture_window(
    hwnd: HWND,
    message: u32,
    w: WPARAM,
    l: LPARAM,
) -> LRESULT {
    match message {
        WM_PRINTCLIENT => {
            let dc = w as HDC;
            // SAFETY: the synchronous caller supplies a private live destination DC.
            // These RGB colors contain no data read from the user's desktop.
            unsafe {
                let red = CreateSolidBrush(0x0000ff);
                let green = CreateSolidBrush(0x00ff00);
                if red.is_null() || green.is_null() {
                    if !red.is_null() {
                        DeleteObject(red);
                    }
                    if !green.is_null() {
                        DeleteObject(green);
                    }
                    return 0;
                }
                let left = RECT {
                    left: 0,
                    top: 0,
                    right: 6,
                    bottom: 8,
                };
                let right = RECT {
                    left: 6,
                    top: 0,
                    right: 12,
                    bottom: 8,
                };
                let okay = FillRect(dc, &left, red) != 0
                    && FillRect(dc, &right, green) != 0
                    && GdiFlush() != 0;
                DeleteObject(red);
                DeleteObject(green);
                isize::from(okay)
            }
        }
        WM_CLOSE => {
            // SAFETY: this is our window on the thread that created it.
            unsafe { DestroyWindow(hwnd) };
            0
        }
        WM_DESTROY => {
            // SAFETY: terminates only this dedicated fixture thread's message loop.
            unsafe { PostQuitMessage(0) };
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, message, w, l) },
    }
}

struct Fixture {
    hwnd: usize,
    thread: u32,
    worker: Option<thread::JoinHandle<()>>,
    ended: mpsc::Receiver<()>,
}
impl Fixture {
    fn open() -> io::Result<Self> {
        let (ready, readiness) = mpsc::channel();
        let (done, ended) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = (|| -> io::Result<()> {
                let _dpi = DpiScope::enter()?;
                // SAFETY: module handle belongs to this process and outlives the class.
                let instance = unsafe { GetModuleHandleW(null()) };
                let class = WNDCLASSW {
                    lpfnWndProc: Some(fixture_window),
                    hInstance: instance,
                    lpszClassName: windows_sys::w!("NestLinkPrivateCaptureFixtureV15"),
                    ..WNDCLASSW::default()
                };
                // SAFETY: test executes once; registration copies the initialized class.
                let atom = unsafe { RegisterClassW(&class) };
                if atom == 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: own class and hidden, never shown or activated window.
                let window = unsafe {
                    CreateWindowExW(
                        WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
                        atom as usize as *const u16,
                        windows_sys::w!("Private pixel fixture"),
                        WS_POPUP,
                        0,
                        0,
                        12,
                        8,
                        null_mut(),
                        null_mut(),
                        instance,
                        null(),
                    )
                };
                if window.is_null() {
                    return Err(io::Error::last_os_error());
                }
                let sent = ready.send(Ok((window as usize, unsafe { GetCurrentThreadId() })));
                if sent.is_err() {
                    unsafe { DestroyWindow(window) };
                    return Ok(());
                }
                let mut message = MSG::default();
                // SAFETY: only this new thread's messages; callback has no user input path.
                while unsafe { GetMessageW(&mut message, null_mut(), 0, 0) } > 0 {
                    unsafe { DispatchMessageW(&message) };
                }
                unsafe { UnregisterClassW(atom as usize as *const u16, instance) };
                Ok(())
            })();
            if let Err(error) = result {
                let _ = ready.send(Err(error));
            }
            let _ = done.send(());
        });
        let (hwnd, thread) = readiness
            .recv_timeout(STARTUP)
            .map_err(io::Error::other)??;
        Ok(Self {
            hwnd,
            thread,
            worker: Some(worker),
            ended,
        })
    }
    fn capture(&self) -> io::Result<WindowsCapture> {
        WindowsCapture::start(
            Arc::new(context()?),
            vec![(
                Target::OwnedWindow {
                    hwnd: self.hwnd,
                    thread: self.thread,
                    width: 12,
                    height: 8,
                },
                display(),
            )],
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: posts only to our owned fixture window; never waits while its DC is borrowed.
        unsafe { PostMessageW(self.hwnd as HWND, WM_CLOSE, 0, 0) };
        let _ = self.ended.recv_timeout(Duration::from_secs(1));
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| worker.is_finished())
            && let Some(worker) = self.worker.take()
        {
            let _ = worker.join();
        }
    }
}
fn next_frame(capture: &mut WindowsCapture) -> io::Result<RawFrame> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(frame) = capture.poll_frame()? {
            return Ok(frame);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture did not paint a frame",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
#[ignore = "requires an actual interactive Windows desktop; captures only a self-created hidden window"]
fn actual_owned_window_pixels_and_os_notifications_end_capture() -> io::Result<()> {
    let fixture = Fixture::open()?;
    let mut capture = fixture.capture()?;
    let first = next_frame(&mut capture)?;
    assert_eq!((first.width, first.height, first.source), (12, 8, 1));
    for (index, pixel) in first.pixels.chunks_exact(4).enumerate() {
        assert_eq!(
            pixel,
            if index % 12 < 6 {
                &[0, 0, 255, 255]
            } else {
                &[0, 255, 0, 255]
            }
        );
    }
    capture.reset()?;
    for (message, w) in [
        (WM_DISPLAYCHANGE, 0),
        (WM_DPICHANGED, 0),
        (WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK as usize),
        (WM_WTSSESSION_CHANGE, WTS_REMOTE_DISCONNECT as usize),
    ] {
        let mut capture = fixture.capture()?;
        let _ = next_frame(&mut capture)?;
        // Synthetic OS notification only to this capture's own hidden observer.
        let observer = capture.shared.observer.load(Ordering::SeqCst) as HWND;
        assert!(!observer.is_null());
        if message == WM_DPICHANGED {
            let suggested = RECT {
                left: 0,
                top: 0,
                right: 1,
                bottom: 1,
            };
            // SAFETY: synchronous-only message to our window; suggested rectangle
            // lives until return. The observer only invalidates its own capture.
            unsafe {
                SendMessageW(
                    observer,
                    message,
                    144 | (144 << 16),
                    (&suggested as *const RECT) as LPARAM,
                )
            };
        } else {
            assert_ne!(unsafe { PostMessageW(observer, message, w, 0) }, 0);
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        while capture.check().is_ok() {
            if Instant::now() >= deadline {
                return Err(io::Error::other("capture did not observe its notification"));
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(capture.poll_frame().is_err());
        let _ = capture.reset();
        assert!(
            capture
                .shared
                .state
                .lock()
                .map_err(|_| io::Error::other("state poisoned"))?
                .frames
                .is_empty()
        );
    }
    let mut stopped = fixture.capture()?;
    let _ = next_frame(&mut stopped)?;
    stopped.reset()?;
    stopped.reset()?;
    assert!(stopped.poll_frame().is_err());
    Ok(())
}
