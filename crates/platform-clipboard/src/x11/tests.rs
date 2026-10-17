use super::*;
use crate::{
    NativeClipboard,
    tests::{authority, binding},
};
use std::{
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    process::{Child, Command, Stdio},
};

struct Server {
    child: Child,
    display: String,
    cookie: Vec<u8>,
    _directory: tempfile::TempDir,
}
impl Server {
    fn open() -> io::Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("nestlink-clipboard-xvfb-")
            .tempdir()?;
        let mut cookie = vec![0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut cookie)?;
        let authority_path = directory.path().join("Xauthority");
        let mut authority = std::fs::File::create(&authority_path)?;
        authority.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        authority.write_all(&65535u16.to_be_bytes())?;
        for field in [&[][..], &[][..], &b"MIT-MAGIC-COOKIE-1"[..], &cookie] {
            authority.write_all(&(field.len() as u16).to_be_bytes())?;
            authority.write_all(field)?;
        }
        drop(authority);
        let mut child = Command::new("Xvfb")
            .args([
                "-displayfd",
                "1",
                "-screen",
                "0",
                "128x128x24",
                "-nolisten",
                "tcp",
                "-noreset",
            ])
            .arg("-auth")
            .arg(&authority_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::from(std::fs::File::create(
                directory.path().join("server.log"),
            )?))
            .spawn()?;
        let result = (|| {
            let stdout = child
                .stdout
                .as_mut()
                .ok_or_else(|| io::Error::other("Xvfb fixture stdout absent"))?;
            // SAFETY: only the owned fixture child pipe is set nonblocking.
            if unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let until = Instant::now() + Duration::from_secs(10);
            let mut bytes = Vec::new();
            while !bytes.contains(&b'\n') {
                if Instant::now() >= until || bytes.len() > 32 {
                    return Err(timed_out("owned Xvfb fixture did not become ready"));
                }
                let mut buffer = [0; 32];
                match stdout.read(&mut buffer) {
                    Ok(0) => return Err(io::Error::other("owned Xvfb fixture exited")),
                    Ok(count) => bytes.extend_from_slice(&buffer[..count]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => return Err(e),
                }
            }
            let display: u16 = std::str::from_utf8(&bytes)
                .map_err(io::Error::other)?
                .trim()
                .parse()
                .map_err(io::Error::other)?;
            Ok(format!(":{display}"))
        })();
        match result {
            Ok(display) => Ok(Self {
                child,
                display,
                cookie,
                _directory: directory,
            }),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let mut diagnostic = String::new();
                std::fs::File::open(directory.path().join("server.log"))?
                    .take(4096)
                    .read_to_string(&mut diagnostic)?;
                Err(io::Error::new(
                    error.kind(),
                    format!("{error}: {diagnostic}"),
                ))
            }
        }
    }
    fn device(&self) -> io::Result<(ClipboardDevice, crate::LocalClipboardApprovalControl)> {
        let display = self.display.clone();
        let expected_peer = self.child.id() as i32;
        let cookie = self.cookie.clone();
        let (approval, control) =
            LocalClipboardApproval::approve_from_local_user(binding(), true, true)?;
        let device = ClipboardDevice::open(binding(), approval, authority(), move |until| {
            let backend = Clipboard::open_with_auth(
                &display,
                None,
                until,
                Some((b"MIT-MAGIC-COOKIE-1".to_vec(), cookie)),
            )?;
            if backend._peer.pid != expected_peer {
                return Err(denied("X11 clipboard test server is not its owned Xvfb"));
            }
            Ok(Box::new(backend))
        })?;
        Ok((device, control))
    }
    fn connection(&self) -> io::Result<Conn> {
        let parsed =
            x11rb_protocol::parse_display::parse_display(Some(&self.display)).map_err(error)?;
        let (conn, peer) = connect_until_auth(
            parsed.display,
            usize::from(parsed.screen),
            Instant::now() + Duration::from_secs(1),
            Some((b"MIT-MAGIC-COOKIE-1".to_vec(), self.cookie.clone())),
        )?;
        if peer.pid != self.child.id() as i32 {
            return Err(denied(
                "X11 clipboard fixture observer reached another server",
            ));
        }
        Ok(conn)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn window(conn: &Conn) -> io::Result<u32> {
    let window = conn.generate_id().map_err(error)?;
    conn.create_window(
        COPY_DEPTH_FROM_PARENT,
        window,
        conn.setup().roots[0].root,
        0,
        0,
        1,
        1,
        0,
        xproto::WindowClass::INPUT_ONLY,
        0,
        &xproto::CreateWindowAux::new().event_mask(xproto::EventMask::PROPERTY_CHANGE),
    )
    .map_err(error)?
    .check()
    .map_err(error)?;
    Ok(window)
}
fn wait_event(conn: &Conn) -> io::Result<Event> {
    let until = Instant::now() + Duration::from_secs(1);
    conn.stream().begin_until(until)?;
    loop {
        if Instant::now() >= until {
            return Err(timed_out("isolated X11 clipboard event missing"));
        }
        if let Some(event) = conn.poll_for_event().map_err(error)? {
            return Ok(event);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
#[test]
#[ignore = "requires an explicitly run, self-owned isolated Xvfb fixture"]
fn owned_xvfb_unicode_roundtrip_and_cleanup() -> io::Result<()> {
    let server = Server::open()?;
    let (mut device, _approval) = server.device()?;
    assert_eq!(device.read_text()?, None);
    let conn = server.connection()?;
    let requester = window(&conn)?;
    let clipboard = atom(&conn, b"CLIPBOARD")?;
    let utf8 = atom(&conn, b"UTF8_STRING")?;
    let property = atom(&conn, b"FIXTURE_TEXT")?;
    device.write_text("中文🙂\nclipboard")?;
    conn.convert_selection(requester, clipboard, utf8, property, CURRENT_TIME)
        .map_err(error)?
        .check()
        .map_err(error)?;
    conn.flush().map_err(error)?;
    let mut accepted = false;
    for _ in 0..64 {
        if let Event::SelectionNotify(event) = wait_event(&conn)? {
            assert_eq!(event.property, property);
            let reply = conn
                .get_property(true, requester, property, utf8, 0, 32768)
                .map_err(error)?
                .reply()
                .map_err(error)?;
            assert_eq!(reply.format, 8);
            assert_eq!(reply.value, "中文🙂\nclipboard".as_bytes());
            accepted = true;
            break;
        }
    }
    assert!(accepted);
    assert_eq!(device.read_text()?, Some("中文🙂\nclipboard".into()));
    device.close()?;
    conn.stream()
        .begin_until(Instant::now() + Duration::from_secs(1))?;
    assert_eq!(
        conn.get_selection_owner(clipboard)
            .map_err(error)?
            .reply()
            .map_err(error)?
            .owner,
        NONE
    );
    assert!(device.write_text("old generation").is_err());
    assert_eq!(
        device.monitor().status().cleanup,
        crate::ClipboardCleanup::Complete
    );
    Ok(())
}
fn external_read(incremental: bool, oversized: bool) -> io::Result<()> {
    let server = Server::open()?;
    let (mut device, _approval) = server.device()?;
    let conn = server.connection()?;
    let owner = window(&conn)?;
    let clipboard = atom(&conn, b"CLIPBOARD")?;
    let utf8 = atom(&conn, b"UTF8_STRING")?;
    let incr = atom(&conn, b"INCR")?;
    conn.set_selection_owner(owner, clipboard, CURRENT_TIME)
        .map_err(error)?
        .check()
        .map_err(error)?;
    conn.flush().map_err(error)?;
    let (served, finished) = std::sync::mpsc::sync_channel(1);
    let fixture = std::thread::spawn(move || -> io::Result<()> {
        loop {
            if let Event::SelectionRequest(request) = wait_event(&conn)? {
                assert_eq!(request.target, utf8);
                let payload = if oversized {
                    vec![b'x'; CLIPBOARD_TEXT_BYTES + 1]
                } else {
                    "external 中文🙂".as_bytes().to_vec()
                };
                if incremental {
                    conn.change_window_attributes(
                        request.requestor,
                        &xproto::ChangeWindowAttributesAux::new()
                            .event_mask(xproto::EventMask::PROPERTY_CHANGE),
                    )
                    .map_err(error)?
                    .check()
                    .map_err(error)?;
                    conn.change_property32(
                        xproto::PropMode::REPLACE,
                        request.requestor,
                        request.property,
                        incr,
                        &[payload.len() as u32],
                    )
                    .map_err(error)?
                    .check()
                    .map_err(error)?;
                } else {
                    conn.change_property8(
                        xproto::PropMode::REPLACE,
                        request.requestor,
                        request.property,
                        utf8,
                        &payload,
                    )
                    .map_err(error)?
                    .check()
                    .map_err(error)?;
                }
                conn.send_event(
                    false,
                    request.requestor,
                    xproto::EventMask::NO_EVENT,
                    xproto::SelectionNotifyEvent {
                        response_type: xproto::SELECTION_NOTIFY_EVENT,
                        sequence: 0,
                        time: request.time,
                        requestor: request.requestor,
                        selection: request.selection,
                        target: request.target,
                        property: request.property,
                    },
                )
                .map_err(error)?
                .check()
                .map_err(error)?;
                conn.flush().map_err(error)?;
                if incremental && !oversized {
                    for chunk in payload.chunks(5).chain(std::iter::once(&[][..])) {
                        loop {
                            if let Event::PropertyNotify(event) = wait_event(&conn)?
                                && event.window == request.requestor
                                && event.atom == request.property
                                && event.state == xproto::Property::DELETE
                            {
                                break;
                            }
                        }
                        conn.change_property8(
                            xproto::PropMode::REPLACE,
                            request.requestor,
                            request.property,
                            utf8,
                            chunk,
                        )
                        .map_err(error)?
                        .check()
                        .map_err(error)?;
                        conn.flush().map_err(error)?;
                    }
                }
                let _ = served.try_send(());
                // Keep this synthetic selection owner alive until after delivery.
                std::thread::sleep(Duration::from_millis(50));
                return Ok(());
            }
        }
    });
    let result = device.read_text();
    finished
        .recv_timeout(Duration::from_secs(1))
        .map_err(io::Error::other)?;
    fixture
        .join()
        .map_err(|_| io::Error::other("isolated selection owner panicked"))??;
    if oversized {
        assert!(result.is_err());
    } else {
        assert_eq!(result?, Some("external 中文🙂".into()));
    }
    device.close()
}
#[test]
#[ignore = "requires an explicitly run, self-owned isolated Xvfb fixture"]
fn owned_xvfb_external_and_incremental_utf8_reads() -> io::Result<()> {
    external_read(false, false)?;
    external_read(true, false)
}
#[test]
#[ignore = "requires an explicitly run, self-owned isolated Xvfb fixture"]
fn owned_xvfb_oversized_peer_data_is_bounded() -> io::Result<()> {
    external_read(false, true)?;
    external_read(true, true)
}
