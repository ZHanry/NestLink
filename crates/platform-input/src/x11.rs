#![allow(unsafe_code)]
use super::{InputCapabilities, NativeInput, denied};
use crate::keys::xkb_name;
use crate::{
    x11_session::X11Session,
    x11_text::X11Text,
    x11_transport::{Conn, IO_BUDGET, Peer, connect, connect_until},
};
use nestlink_remote::input::{Button, InputAction, InputDevice, InputLayout, PlatformInput};
use std::{collections::BTreeMap, io, time::Instant};
use x11rb::{
    connection::Connection,
    protocol::{
        randr::ConnectionExt as _,
        screensaver::ConnectionExt as _,
        xkb::{self, ConnectionExt as _},
        xproto::{self, ConnectionExt as _, Keycode},
        xtest::ConnectionExt as _,
    },
};
#[cfg(test)]
use {
    crate::x11_transport::{BoundedStream, Wire},
    std::{os::unix::net::UnixStream, time::Duration},
    x11rb::rust_connection::{DefaultStream, PollMode, Stream},
};
#[derive(Debug, Clone, PartialEq, Eq)]
struct Facts {
    bounds: [u16; 2],
    names: Vec<[u8; 4]>,
    first_key: u8,
    group: u8,
    keysyms: Vec<u32>,
    monitors: Vec<[i64; 7]>,
}
fn facts(conn: &Conn, root: u32) -> io::Result<Facts> {
    let geometry = conn
        .get_geometry(root)
        .map_err(io::Error::other)?
        .reply()
        .map_err(io::Error::other)?;
    if geometry.width == 0
        || geometry.height == 0
        || geometry.width > 32768
        || geometry.height > 32768
    {
        return Err(denied("X11 root layout exceeds budget"));
    }
    let names = conn
        .xkb_get_names(xkb::ID::USE_CORE_KBD.into(), xkb::NameDetail::KEY_NAMES)
        .map_err(io::Error::other)?
        .reply()
        .map_err(io::Error::other)?;
    let key_names = names
        .value_list
        .key_names
        .ok_or_else(|| denied("XKB physical key names unavailable"))?;
    if key_names.len() > 256 || key_names.len() != usize::from(names.n_keys) {
        return Err(denied("XKB key name budget mismatch"));
    }
    let names_values = key_names.into_iter().map(|n| n.name).collect();
    let state = conn
        .xkb_get_state(xkb::ID::USE_CORE_KBD.into())
        .map_err(io::Error::other)?
        .reply()
        .map_err(io::Error::other)?;
    let count = conn
        .setup()
        .max_keycode
        .checked_sub(conn.setup().min_keycode)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| denied("X11 keycode range invalid"))?;
    let keysyms = conn
        .get_keyboard_mapping(conn.setup().min_keycode, count)
        .map_err(io::Error::other)?
        .reply()
        .map_err(io::Error::other)?
        .keysyms;
    if keysyms.len() > 8192 {
        return Err(denied("X11 keymap exceeds budget"));
    }
    let monitors = conn
        .randr_get_monitors(root, true)
        .map_err(io::Error::other)?
        .reply()
        .map_err(io::Error::other)?
        .monitors;
    if monitors.is_empty() || monitors.len() > 64 {
        return Err(denied("RandR monitor facts unavailable"));
    }
    let mut monitors: Vec<_> = monitors
        .into_iter()
        .map(|m| {
            [
                i64::from(m.x),
                i64::from(m.y),
                i64::from(m.width),
                i64::from(m.height),
                i64::from(m.width_in_millimeters),
                i64::from(m.height_in_millimeters),
                i64::from(m.primary),
            ]
        })
        .collect();
    monitors.sort();
    let saver = conn
        .screensaver_query_info(root)
        .map_err(io::Error::other)?
        .reply()
        .map_err(io::Error::other)?;
    if saver.state == 1 {
        return Err(denied("X11 screen saver is active; input stopped"));
    }
    Ok(Facts {
        bounds: [geometry.width, geometry.height],
        names: names_values,
        first_key: names.first_key,
        group: state.group.into(),
        keysyms,
        monitors,
    })
}
/// Explicit local X11 desktop profile. Wayland hosts must select the portal
/// adapter rather than automatically using an XWayland display as a fallback.
pub struct X11Input {
    session: Option<X11Session>,
    text: X11Text,
    conn: Conn,
    peer: Peer,
    display: u16,
    screen: usize,
    root: u32,
    original: Facts,
    held: BTreeMap<Button, Keycode>,
    cleanup_until: Option<Instant>,
    terminal: bool,
    scroll_remainder: [i32; 2],
}
impl X11Input {
    pub fn open(display: &str) -> io::Result<Self> {
        Self::open_for_desktop(display, std::process::id())
    }
    /// Bind input to this GUI or an authenticated local GUI IPC peer's login
    /// session. The PID must never be selected by a remote caller.
    pub fn open_for_desktop(display: &str, local_gui_pid: u32) -> io::Result<Self> {
        let session = X11Session::open(local_gui_pid, display)?;
        Self::open_bound(display, Some(session))
    }
    #[cfg(test)]
    fn open_without_session(display: &str) -> io::Result<Self> {
        Self::open_bound(display, None)
    }
    fn open_bound(display: &str, session: Option<X11Session>) -> io::Result<Self> {
        let parsed = x11rb_protocol::parse_display::parse_display(Some(display))
            .map_err(io::Error::other)?;
        if !parsed.host.is_empty()
            || parsed.protocol.is_some()
            || display.len() > 32
            || !display.starts_with(':')
        {
            return Err(denied("input requires an explicit local Unix X11 display"));
        }
        let (conn, peer) = connect(parsed.display, usize::from(parsed.screen))?;
        conn.stream().begin()?;
        let xtest = conn
            .xtest_get_version(2, 2)
            .map_err(io::Error::other)?
            .reply()
            .map_err(io::Error::other)?;
        if xtest.major_version != 2 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "XTEST 2 input extension required",
            ));
        }
        let xkb = conn
            .xkb_use_extension(1, 0)
            .map_err(io::Error::other)?
            .reply()
            .map_err(io::Error::other)?;
        if !xkb.supported {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "XKB input extension required",
            ));
        }
        let root = conn
            .setup()
            .roots
            .get(usize::from(parsed.screen))
            .ok_or_else(|| denied("X11 screen unavailable"))?
            .root;
        let mut original = facts(&conn, root)?;
        let text = X11Text::new(&conn)?;
        text.canonicalize(&mut original.keysyms)?;
        Ok(Self {
            session,
            text,
            conn,
            peer,
            display: parsed.display,
            screen: usize::from(parsed.screen),
            root,
            original,
            held: BTreeMap::new(),
            cleanup_until: None,
            terminal: false,
            scroll_remainder: [0; 2],
        })
    }
    fn check_until(&mut self, until: Instant) -> io::Result<()> {
        if self.terminal {
            return Err(denied("X11 input adapter is terminal"));
        }
        let result = (|| {
            if let Some(session) = &self.session {
                session.check_until(until)?;
            }
            self.conn.stream().begin_until(until)?;
            let mut current = facts(&self.conn, self.root)?;
            self.text.canonicalize(&mut current.keysyms)?;
            if current != self.original {
                return Err(denied("X11 keymap, group, display or monitor changed"));
            }
            Ok(())
        })();
        if result.is_err() {
            self.terminal = true;
        }
        result
    }
    fn keycode(&self, usage: u16) -> io::Result<u8> {
        let name = xkb_name(usage).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "HID usage unavailable in XKB")
        })?;
        let index = self
            .original
            .names
            .iter()
            .position(|n| *n == name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "physical key absent from XKB layout",
                )
            })?;
        self.original
            .first_key
            .checked_add(u8::try_from(index).map_err(io::Error::other)?)
            .ok_or_else(|| denied("XKB keycode overflow"))
    }
    fn event(&self, kind: u8, detail: u8, x: i16, y: i16) -> io::Result<()> {
        self.conn
            .xtest_fake_input(kind, detail, x11rb::CURRENT_TIME, self.root, x, y, 0)
            .map_err(io::Error::other)?
            .check()
            .map_err(io::Error::other)
    }
    fn release(&mut self, button: Button) -> io::Result<()> {
        if let Some(code) = self.held.get(&button).copied() {
            if self.cleanup_until.is_none() {
                self.conn.stream().begin()?;
            }
            self.event(
                match button {
                    Button::Key(_) => xproto::KEY_RELEASE_EVENT,
                    Button::Pointer(_) => xproto::BUTTON_RELEASE_EVENT,
                },
                code,
                0,
                0,
            )?;
            self.held.remove(&button);
        }
        Ok(())
    }
}
impl NativeInput for X11Input {
    fn layout(&self) -> InputLayout {
        InputLayout {
            left: 0,
            top: 0,
            width: u32::from(self.original.bounds[0]),
            height: u32::from(self.original.bounds[1]),
        }
    }
    fn capabilities(&self) -> InputCapabilities {
        InputCapabilities {
            physical_keys: true,
            pointer_buttons: true,
            text_commit: true,
        }
    }
}
impl InputDevice for X11Input {
    fn check(&mut self) -> io::Result<()> {
        self.check_until(Instant::now() + IO_BUDGET)
    }
    fn begin_reset(&mut self) -> io::Result<()> {
        self.scroll_remainder = [0; 2];
        self.terminal = true;
        let until = Instant::now() + IO_BUDGET;
        self.cleanup_until = Some(until);
        self.conn.stream().begin_until(until)
    }
    fn reset(&mut self) -> io::Result<()> {
        self.terminal = true;
        let until = *self
            .cleanup_until
            .get_or_insert_with(|| Instant::now() + IO_BUDGET);
        if !self.held.is_empty() || self.text.needs_cleanup() {
            // On a failed bounded request, only reconnect to the identical
            // live server (including process start time) for cleanup.
            if self.conn.stream().remaining().is_err() {
                let (conn, peer) = connect_until(self.display, self.screen, until)?;
                if peer != self.peer {
                    return Err(denied("X11 server changed during input cleanup"));
                }
                self.conn = conn;
                self.conn.stream().begin_until(until)?;
            }
            let mut first = None;
            for button in self.held.keys().copied().collect::<Vec<_>>() {
                if let Err(error) = self.release(button)
                    && first.is_none()
                {
                    first = Some(error);
                }
            }
            if let Err(error) = self.text.reset(&self.conn, self.root)
                && first.is_none()
            {
                first = Some(error);
            }
            self.cleanup_until = None;
            if let Some(error) = first {
                return Err(error);
            }
        }
        self.cleanup_until = None;
        Ok(())
    }
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        if let PlatformInput::Release(button) = input {
            return self.release(button);
        }
        let until = Instant::now() + IO_BUDGET;
        self.check_until(until)?;
        self.conn.stream().begin_until(until)?;
        match input {
            PlatformInput::Action(InputAction::Key { code, down }) => {
                let native = self.keycode(*code)?;
                let button = Button::Key(*code);
                if *down {
                    self.held.insert(button, native);
                } else if !self.held.contains_key(&button) {
                    return Ok(());
                }
                self.event(
                    if *down {
                        xproto::KEY_PRESS_EVENT
                    } else {
                        xproto::KEY_RELEASE_EVENT
                    },
                    native,
                    0,
                    0,
                )?;
                if !down {
                    self.held.remove(&button);
                }
                Ok(())
            }
            PlatformInput::Action(InputAction::Pointer { button, down, x, y }) => {
                if *x < 0
                    || *y < 0
                    || *x >= i32::from(self.original.bounds[0])
                    || *y >= i32::from(self.original.bounds[1])
                {
                    return Err(denied("pointer outside X11 root"));
                }
                self.event(xproto::MOTION_NOTIFY_EVENT, 0, *x as i16, *y as i16)?;
                if let Some(button) = button {
                    let native = match button {
                        1 => 1,
                        2 => 3,
                        3 => 2,
                        4 => 8,
                        5 => 9,
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "unknown pointer button",
                            ));
                        }
                    };
                    if *down {
                        self.held.insert(Button::Pointer(*button), native);
                    } else if !self.held.contains_key(&Button::Pointer(*button)) {
                        return Ok(());
                    }
                    self.event(
                        if *down {
                            xproto::BUTTON_PRESS_EVENT
                        } else {
                            xproto::BUTTON_RELEASE_EVENT
                        },
                        native,
                        0,
                        0,
                    )?;
                    if !down {
                        self.held.remove(&Button::Pointer(*button));
                    }
                }
                Ok(())
            }
            PlatformInput::Action(InputAction::Scroll { x, y }) => {
                for (axis, delta, positive, negative) in [(0, *x, 7, 6), (1, *y, 4, 5)] {
                    self.scroll_remainder[axis] += delta;
                    while self.scroll_remainder[axis].unsigned_abs() >= 120 {
                        let direction = self.scroll_remainder[axis].signum();
                        let button = if direction > 0 { positive } else { negative };
                        self.event(xproto::BUTTON_PRESS_EVENT, button, 0, 0)?;
                        self.event(xproto::BUTTON_RELEASE_EVENT, button, 0, 0)?;
                        self.scroll_remainder[axis] -= direction * 120;
                    }
                }
                Ok(())
            }
            PlatformInput::Action(InputAction::Text(text)) => {
                if !self.held.is_empty() {
                    return Err(denied(
                        "release remote keys and buttons before X11 text input",
                    ));
                }
                self.text.commit(&self.conn, self.root, text)
            }
            PlatformInput::Release(_) => unreachable!(),
        }
    }
}
impl Drop for X11Input {
    fn drop(&mut self) {
        let _ = self.begin_reset();
        let _ = self.reset();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nestlink_auth::random_id;
    use nestlink_identity::{InstallationIdentity, PermitSigner, verify_permit};
    use nestlink_policy::PathSet;
    use nestlink_protocol::{Path, Permission, PermitClaims};
    use nestlink_remote::{
        AuthorizedConnection, ChannelRuntime, CleanupStatus, RuntimeClock, SessionLifecycle,
        input::{InputController, InputEpoch, InputEvent},
    };
    use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
    use prost::Message;
    use tokio::{io::split, sync::watch};
    use x11rb::protocol::{
        render::{self, ConnectionExt as _},
        xfixes::ConnectionExt as _,
    };

    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
    type RuntimeFixture<D> = (
        ChannelRuntime,
        InputController<D>,
        watch::Sender<Option<StopReason>>,
        tokio::io::DuplexStream,
    );
    pub(crate) fn create_runtime<D: NativeInput>(device: D) -> Result<RuntimeFixture<D>> {
        let controller = InstallationIdentity::generate();
        let host = InstallationIdentity::generate();
        let clock = RuntimeClock::default();
        let now = clock.sample()?;
        let binding = SessionBinding {
            deployment_id: random_id(),
            security_epoch: 1,
            session_id: random_id(),
            account_id: random_id(),
            controller_device_id: random_id(),
            host_device_id: random_id(),
            controller_key_sha256: controller.fingerprint(),
            host_key_sha256: host.fingerprint(),
            resource_id: random_id(),
            policy_revision: 1,
            connection_generation: 9,
            capability_sha256: [9; 32],
            granted_permissions: vec![Permission::View, Permission::Input],
            supported_capabilities: vec!["vp8".into()],
            local_paths: PathSet::DIRECT,
        };
        let claims = PermitClaims {
            schema_version: 1,
            deployment_id: binding.deployment_id.clone(),
            security_epoch: 1,
            session_id: binding.session_id.clone(),
            account_id: binding.account_id.clone(),
            controller_device_id: binding.controller_device_id.clone(),
            host_device_id: binding.host_device_id.clone(),
            controller_key_sha256: controller.fingerprint().to_vec(),
            host_key_sha256: host.fingerprint().to_vec(),
            resource_id: binding.resource_id.clone(),
            permissions: vec![Permission::View as i32, Permission::Input as i32],
            paths: vec![Path::Direct as i32],
            policy_revision: 1,
            connection_generation: 9,
            lease_sequence: 1,
            issued_at_unix_ms: now.unix_ms,
            expires_at_unix_ms: now.unix_ms + 15000,
            capability_sha256: vec![9; 32],
            required_capabilities: vec!["vp8".into()],
        };
        let signer = PermitSigner::generate();
        let mut session = Session::activate(
            verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?,
            binding,
            Path::Direct,
            now.monotonic_ms,
            now,
        )?;
        for (role, identity) in [
            (EndpointRole::Controller, controller),
            (EndpointRole::Host, host),
        ] {
            let transcript = session.proof_transcript();
            session.confirm_endpoint(
                role,
                &identity.public_key(),
                &identity.prove(&transcript)?,
                clock.monotonic_ms(),
            )?;
        }
        let (stop, stopped) = watch::channel(None);
        let (peer, stream) = tokio::io::duplex(64);
        let (read, write) = split(stream);
        let runtime = AuthorizedConnection::with_lifecycle(
            read,
            write,
            session,
            Path::Direct,
            clock,
            SessionLifecycle::new(stopped),
        )?
        .into_channels();
        let layout = device.layout();
        let input = InputController::attach(
            runtime.lease_control(),
            device,
            InputEpoch {
                input: 1,
                layout: 1,
                connection: 9,
            },
            layout,
        )?;
        Ok((runtime, input, stop, peer))
    }
    fn apply(input: &InputController<X11Input>, sequence: u64, action: InputAction) -> Result {
        assert!(input.apply(&InputEvent {
            epoch: InputEpoch {
                input: 1,
                layout: 1,
                connection: 9
            },
            sequence,
            action
        })?);
        Ok(())
    }
    fn pressed(conn: &Conn, key: u8) -> Result<bool> {
        conn.stream().begin()?;
        let keys = conn.query_keymap()?.reply()?.keys;
        Ok(keys[usize::from(key / 8)] & (1 << (key % 8)) != 0)
    }
    #[test]
    fn untrusted_reply_lengths_and_server_stalls_close_the_stream() -> io::Result<()> {
        let mut wire = Wire {
            setup: false,
            header: [0; 32],
            used: 0,
            body: 0,
        };
        let mut header = [0; 32];
        header[0] = 1;
        header[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(wire.observe(&header[..7]).is_ok());
        assert!(wire.observe(&header[7..]).is_err());
        let (_server, client) = UnixStream::pair()?;
        let (raw, _) = DefaultStream::from_unix_stream(client)?;
        let stream = BoundedStream::new(raw);
        let started = Instant::now();
        assert!(stream.poll(PollMode::Readable).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(stream.begin().is_err());
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires scripts/refactor-x11-input.py and its owned authenticated Xvfb"]
    async fn actual_isolated_x11_input_and_idle_platform_change() -> Result {
        let display = std::env::var("NESTLINK_TEST_X11_DISPLAY")?;
        let server: i32 = std::env::var("NESTLINK_TEST_X11_PID")?.parse()?;
        let mut device = X11Input::open_without_session(&display)?;
        assert_eq!(device.peer.pid, server);
        let stat = std::fs::read_to_string(format!("/proc/{server}/stat"))?;
        let tail = stat.rsplit_once(") ").ok_or("invalid owned server stat")?.1;
        let parent: i32 = tail
            .split_whitespace()
            .nth(1)
            .ok_or("server parent unavailable")?
            .parse()?;
        // SAFETY: scalar process identity; no mutation until the owned-server check passes.
        assert_eq!(parent, unsafe { libc::getppid() });
        assert_eq!(
            std::fs::read_to_string(format!("/proc/{server}/comm"))?.trim(),
            "Xvfb"
        );
        let a = device.keycode(4)?;
        let right_ctrl = device.keycode(0xe4)?;
        let (observer, peer) = connect(device.display, device.screen)?;
        assert_eq!(peer, device.peer);
        observer.stream().begin()?;
        let window = observer.generate_id()?;
        observer
            .create_window(
                x11rb::COPY_DEPTH_FROM_PARENT,
                window,
                device.root,
                0,
                0,
                800,
                600,
                0,
                xproto::WindowClass::INPUT_OUTPUT,
                0,
                &xproto::CreateWindowAux::new().event_mask(
                    xproto::EventMask::KEY_PRESS
                        | xproto::EventMask::KEY_RELEASE
                        | xproto::EventMask::BUTTON_PRESS
                        | xproto::EventMask::BUTTON_RELEASE,
                ),
            )?
            .check()?;
        observer.map_window(window)?.check()?;
        observer
            .set_input_focus(xproto::InputFocus::PARENT, window, x11rb::CURRENT_TIME)?
            .check()?;
        let root = device.root;
        // A separate authenticated capture connection observes a real owned
        // window. Its target event loop changes pixels only after XTEST input.
        let mut capture = crate::X11CaptureSource::open_without_session(&display)?;
        let captured_source = capture.displays()[0].source;
        let gc = observer.generate_id()?;
        observer.stream().begin()?;
        observer
            .create_gc(
                gc,
                window,
                &xproto::CreateGCAux::new().foreground(0x00ff0000),
            )?
            .check()?;
        let rectangle = xproto::Rectangle {
            x: 0,
            y: 0,
            width: 800,
            height: 600,
        };
        observer
            .poly_fill_rectangle(window, gc, &[rectangle])?
            .check()?;
        let frame = capture.capture_until(captured_source, Instant::now() + IO_BUDGET)?;
        let position = (20 * frame.width as usize + 20) * 4;
        assert_eq!(&frame.pixels[position..position + 4], &[0, 0, 255, 255]);
        device.inject(PlatformInput::Action(&InputAction::Key {
            code: 4,
            down: true,
        }))?;
        device.inject(PlatformInput::Action(&InputAction::Key {
            code: 4,
            down: false,
        }))?;
        observer.stream().begin()?;
        let mut target_received_key = false;
        for _ in 0..100 {
            match observer.poll_for_event()? {
                Some(x11rb::protocol::Event::KeyPress(event)) if event.detail == a => {
                    target_received_key = true;
                    observer
                        .change_gc(gc, &xproto::ChangeGCAux::new().foreground(0x0000ff00))?
                        .check()?;
                    observer
                        .poly_fill_rectangle(window, gc, &[rectangle])?
                        .check()?;
                }
                Some(_) => {}
                None => break,
            }
        }
        assert!(target_received_key);
        let frame = capture.capture_until(captured_source, Instant::now() + IO_BUDGET)?;
        assert_eq!(&frame.pixels[position..position + 4], &[0, 255, 0, 255]);
        // Render creates an owned ARGB cursor with a nonzero hotspot and one
        // translucent pixel. XFixes returns the actual server cursor, which
        // the source must composite without reading it from root ZPixmap.
        observer.stream().begin()?;
        observer.render_query_version(0, 11)?.reply()?;
        let formats = observer.render_query_pict_formats()?.reply()?;
        let argb = formats
            .formats
            .iter()
            .find(|f| {
                f.depth == 32
                    && f.type_ == render::PictType::DIRECT
                    && f.direct.alpha_shift == 24
                    && f.direct.alpha_mask == 255
                    && f.direct.red_shift == 16
                    && f.direct.red_mask == 255
                    && f.direct.green_shift == 8
                    && f.direct.green_mask == 255
                    && f.direct.blue_shift == 0
                    && f.direct.blue_mask == 255
            })
            .ok_or("ARGB cursor format unavailable")?
            .id;
        let pixmap = observer.generate_id()?;
        let picture = observer.generate_id()?;
        let cursor_gc = observer.generate_id()?;
        let cursor = observer.generate_id()?;
        observer.create_pixmap(32, pixmap, root, 2, 2)?.check()?;
        observer
            .create_gc(cursor_gc, pixmap, &xproto::CreateGCAux::new())?
            .check()?;
        let cursor_pixels = [0xff0000ffu32, 0x80800000, 0, 0xffffff00];
        let cursor_bytes: Vec<u8> = cursor_pixels
            .iter()
            .flat_map(|pixel| {
                if observer.setup().image_byte_order == xproto::ImageOrder::LSB_FIRST {
                    pixel.to_le_bytes()
                } else {
                    pixel.to_be_bytes()
                }
            })
            .collect();
        observer
            .put_image(
                xproto::ImageFormat::Z_PIXMAP,
                pixmap,
                cursor_gc,
                2,
                2,
                0,
                0,
                0,
                32,
                &cursor_bytes,
            )?
            .check()?;
        observer
            .render_create_picture(picture, pixmap, argb, &render::CreatePictureAux::new())?
            .check()?;
        observer
            .render_create_cursor(cursor, picture, 1, 1)?
            .check()?;
        observer
            .change_window_attributes(
                window,
                &xproto::ChangeWindowAttributesAux::new().cursor(cursor),
            )?
            .check()?;
        device.inject(PlatformInput::Action(&InputAction::Pointer {
            button: None,
            down: false,
            x: 32,
            y: 40,
        }))?;
        observer.stream().begin()?;
        observer.xfixes_query_version(1, 0)?.reply()?;
        let actual_cursor = observer.xfixes_get_cursor_image()?.reply()?;
        assert_eq!(
            (
                actual_cursor.x,
                actual_cursor.y,
                actual_cursor.xhot,
                actual_cursor.yhot
            ),
            (32, 40, 1, 1)
        );
        assert_eq!(actual_cursor.cursor_image, cursor_pixels);
        let frame = capture.capture_until(captured_source, Instant::now() + IO_BUDGET)?;
        let at = |x: usize, y: usize| {
            &frame.pixels
                [(y * frame.width as usize + x) * 4..(y * frame.width as usize + x) * 4 + 4]
        };
        assert_eq!(at(31, 39), &[255, 0, 0, 255]);
        assert_eq!(at(32, 39), &[0, 127, 128, 255]);
        assert_eq!(at(31, 40), &[0, 255, 0, 255]);
        assert_eq!(at(32, 40), &[0, 255, 255, 255]);
        // Characterize the visibility gap on this owned Xvfb, not the user's
        // display. XFixes explicitly keeps cursor notifications while hidden
        // and supplies no visibility field in GetCursorImage. This result is
        // an implementation limitation, not hidden-cursor acceptance.
        observer.stream().begin()?;
        let version = observer.xfixes_query_version(4, 0)?.reply()?;
        assert!(version.major_version >= 4);
        observer.xfixes_hide_cursor(window)?.check()?;
        let hidden_cursor = observer.xfixes_get_cursor_image()?.reply();
        // Restore our own HideCursor request even when the diagnostic failed.
        observer.xfixes_show_cursor(window)?.check()?;
        let hidden_cursor = hidden_cursor?;
        assert_eq!(hidden_cursor.cursor_serial, actual_cursor.cursor_serial);
        assert_eq!(hidden_cursor.cursor_image, actual_cursor.cursor_image);
        assert_eq!(
            (
                hidden_cursor.x,
                hidden_cursor.y,
                hidden_cursor.width,
                hidden_cursor.height,
                hidden_cursor.xhot,
                hidden_cursor.yhot
            ),
            (
                actual_cursor.x,
                actual_cursor.y,
                actual_cursor.width,
                actual_cursor.height,
                actual_cursor.xhot,
                actual_cursor.yhot
            )
        );
        println!(
            "XFixes visibility limitation observed: HideCursor leaves GetCursorImage position, geometry, serial and pixels unchanged; hidden-cursor adaptation remains incomplete."
        );
        observer.stream().begin()?;
        observer
            .change_window_attributes(
                window,
                &xproto::ChangeWindowAttributesAux::new().cursor(x11rb::NONE),
            )?
            .check()?;
        observer.free_cursor(cursor)?.check()?;
        observer.render_free_picture(picture)?.check()?;
        observer.free_pixmap(pixmap)?.check()?;
        observer.free_gc(cursor_gc)?.check()?;
        let capture_control = capture.control();
        assert!(capture_control.is_active());
        let mut expired_capture = crate::X11CaptureSource::open_without_session(&display)?;
        assert!(
            expired_capture
                .capture_until(captured_source, Instant::now())
                .is_err()
        );
        assert!(
            expired_capture
                .check_until(Instant::now() + IO_BUDGET)
                .is_err()
        );
        let before_text = device.original.keysyms.clone();
        device.inject(PlatformInput::Action(&InputAction::Text("a中😀\n".into())))?;
        device.check()?;
        // Input-owned Unicode mappings are unrelated to display authority.
        capture.check_until(Instant::now() + IO_BUDGET)?;
        capture.close()?;
        assert!(!capture_control.is_active());
        assert!(
            capture
                .capture_until(captured_source, Instant::now() + IO_BUDGET)
                .is_err()
        );
        assert!(capture.check_until(Instant::now() + IO_BUDGET).is_err());
        // Read through a distinct X11 client, after all commits have completed:
        // the keycodes still denote the original characters rather than a
        // last-character/reverted mapping. This is a keysym contract test;
        // real toolkit/XIM composition is a separate acceptance requirement.
        observer.stream().begin()?;
        let mut received = Vec::new();
        for _ in 0..100 {
            match observer.poll_for_event()? {
                Some(x11rb::protocol::Event::KeyPress(event)) => {
                    let symbols = observer.get_keyboard_mapping(event.detail, 1)?.reply()?;
                    received.push(symbols.keysyms[0]);
                }
                Some(_) => {}
                None => break,
            }
        }
        assert_eq!(
            received,
            vec![u32::from('a'), 0x01004e2d, 0x0101f600, 0xff0d]
        );
        let mut saver_capture = crate::X11CaptureSource::open_without_session(&display)?;
        observer.stream().begin()?;
        observer
            .force_screen_saver(xproto::ScreenSaver::ACTIVE)?
            .check()?;
        let denied_by_saver = saver_capture
            .check_until(Instant::now() + IO_BUDGET)
            .is_err();
        observer.stream().begin()?;
        observer
            .force_screen_saver(xproto::ScreenSaver::RESET)?
            .check()?;
        assert!(
            denied_by_saver,
            "capture must stop on the actual owned screen saver"
        );
        assert!(
            saver_capture
                .capture_until(captured_source, Instant::now() + IO_BUDGET)
                .is_err()
        );
        let (mut runtime, input, _stop, _transport_peer) = create_runtime(device)?;
        apply(
            &input,
            1,
            InputAction::Key {
                code: 4,
                down: true,
            },
        )?;
        apply(
            &input,
            2,
            InputAction::Key {
                code: 0xe4,
                down: true,
            },
        )?;
        apply(
            &input,
            3,
            InputAction::Pointer {
                button: Some(1),
                down: true,
                x: 210,
                y: 125,
            },
        )?;
        assert!(pressed(&observer, a)?);
        assert!(pressed(&observer, right_ctrl)?);
        observer.stream().begin()?;
        let pointer = observer.query_pointer(root)?.reply()?;
        assert_eq!((pointer.root_x, pointer.root_y), (210, 125));
        assert!(pointer.mask.contains(xproto::KeyButMask::BUTTON1));
        runtime.lease_control().stop(StopReason::Revoked)?;
        let report = tokio::time::timeout(Duration::from_secs(2), runtime.wait_stopped()).await??;
        assert_eq!(report.reason, StopReason::Revoked);
        assert_eq!(report.cleanup, CleanupStatus::Succeeded);
        assert!(!pressed(&observer, a)?);
        assert!(!pressed(&observer, right_ctrl)?);
        observer.stream().begin()?;
        assert_eq!(
            observer
                .get_keyboard_mapping(
                    observer.setup().min_keycode,
                    observer.setup().max_keycode - observer.setup().min_keycode + 1
                )?
                .reply()?
                .keysyms,
            before_text
        );
        assert!(
            !observer
                .query_pointer(root)?
                .reply()?
                .mask
                .contains(xproto::KeyButMask::BUTTON1)
        );
        drop(input);
        drop(runtime);

        let mut exhausted = X11Input::open_without_session(&display)?;
        let oversized_alphabet: String = (0xe000..0xe200).filter_map(char::from_u32).collect();
        assert!(
            exhausted
                .inject(PlatformInput::Action(&InputAction::Text(
                    oversized_alphabet
                )))
                .is_err()
        );
        assert!(
            !exhausted.text.needs_cleanup(),
            "capacity preflight must run before mapping or input"
        );
        assert!(
            exhausted.check().is_err(),
            "an error does not reopen text authority"
        );
        drop(exhausted);

        let mut owned_text = X11Input::open_without_session(&display)?;
        owned_text.inject(PlatformInput::Action(&InputAction::Text("中".into())))?;
        observer.stream().begin()?;
        let count = observer.setup().max_keycode - observer.setup().min_keycode + 1;
        let map = observer
            .get_keyboard_mapping(observer.setup().min_keycode, count)?
            .reply()?;
        let width = usize::from(map.keysyms_per_keycode);
        let index = map
            .keysyms
            .chunks(width)
            .position(|row| row[0] == 0x01004e2d)
            .ok_or("owned Unicode mapping absent")?;
        let external_row = vec![0x01004e2e; width];
        let code = observer.setup().min_keycode + u8::try_from(index)?;
        observer
            .change_keyboard_mapping(1, code, map.keysyms_per_keycode, &external_row)?
            .check()?;
        let external = observer
            .get_keyboard_mapping(observer.setup().min_keycode, count)?
            .reply()?
            .keysyms;
        assert!(owned_text.check().is_err());
        let _ = owned_text.begin_reset();
        assert!(
            owned_text.reset().is_err(),
            "foreign remap is preserved and reported"
        );
        observer.stream().begin()?;
        assert_eq!(
            observer
                .get_keyboard_mapping(observer.setup().min_keycode, count)?
                .reply()?
                .keysyms,
            external
        );
        observer
            .change_keyboard_mapping(
                1,
                code,
                map.keysyms_per_keycode,
                &before_text[index * width..(index + 1) * width],
            )?
            .check()?;
        drop(owned_text);

        let device = X11Input::open_without_session(&display)?;
        let original = device.original.keysyms.clone();
        let min = observer.setup().min_keycode;
        let count = observer.setup().max_keycode - min + 1;
        observer.stream().begin()?;
        let mapping = observer.get_keyboard_mapping(min, count)?.reply()?;
        let width = usize::from(mapping.keysyms_per_keycode);
        let (mut runtime, input, _stop, _transport_peer) = create_runtime(device)?;
        apply(
            &input,
            1,
            InputAction::Key {
                code: 4,
                down: true,
            },
        )?;
        let mut changed = original.clone();
        changed[usize::from(a - min) * width] = 0x62;
        observer.stream().begin()?;
        observer
            .change_keyboard_mapping(count, min, mapping.keysyms_per_keycode, &changed)?
            .check()?;
        // No business event is sent: the idle supervisor detects the OS change.
        let report = tokio::time::timeout(Duration::from_secs(2), runtime.wait_stopped()).await??;
        assert_eq!(report.reason, StopReason::PlatformChanged);
        assert_eq!(report.cleanup, CleanupStatus::Succeeded);
        assert!(!pressed(&observer, a)?);
        assert!(
            input
                .apply(&InputEvent {
                    epoch: InputEpoch {
                        input: 1,
                        layout: 1,
                        connection: 9
                    },
                    sequence: 2,
                    action: InputAction::Key {
                        code: 4,
                        down: true
                    }
                })
                .is_err()
        );
        observer.stream().begin()?;
        observer
            .change_keyboard_mapping(count, min, mapping.keysyms_per_keycode, &original)?
            .check()?;
        drop(input);
        drop(runtime);

        let mut device = X11Input::open_without_session(&display)?;
        // Unowned release must not alter a key held by another local source.
        observer.stream().begin()?;
        observer
            .xtest_fake_input(
                xproto::KEY_PRESS_EVENT,
                a,
                x11rb::CURRENT_TIME,
                root,
                0,
                0,
                0,
            )?
            .check()?;
        device.inject(PlatformInput::Action(&InputAction::Key {
            code: 4,
            down: false,
        }))?;
        assert!(pressed(&observer, a)?);
        observer.stream().begin()?;
        observer
            .xtest_fake_input(
                xproto::KEY_RELEASE_EVENT,
                a,
                x11rb::CURRENT_TIME,
                root,
                0,
                0,
                0,
            )?
            .check()?;
        device.inject(PlatformInput::Action(&InputAction::Key {
            code: 4,
            down: true,
        }))?;
        drop(device);
        assert!(!pressed(&observer, a)?);

        let device = X11Input::open_without_session(&display)?;
        let (mut runtime, input, _stop, _transport_peer) = create_runtime(device)?;
        apply(
            &input,
            1,
            InputAction::Key {
                code: 4,
                down: true,
            },
        )?;
        struct Resume(i32);
        impl Drop for Resume {
            fn drop(&mut self) {
                // SAFETY: the PID was matched to this harness's live child
                // before use, and its parent reaps it only after this test.
                unsafe {
                    libc::kill(self.0, libc::SIGCONT);
                }
            }
        }
        let resume = Resume(server);
        // SAFETY: only the verified, owned isolated Xvfb is stopped.
        assert_eq!(unsafe { libc::kill(server, libc::SIGSTOP) }, 0);
        let started = Instant::now();
        let report = tokio::time::timeout(Duration::from_secs(2), runtime.wait_stopped()).await??;
        assert_eq!(report.reason, StopReason::PlatformChanged);
        assert!(matches!(report.cleanup, CleanupStatus::Failed(_)));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(resume);
        // The terminated business connection never revives; final release may
        // reconnect only to the same process after it responds again.
        assert!(
            input
                .apply(&InputEvent {
                    epoch: InputEpoch {
                        input: 1,
                        layout: 1,
                        connection: 9
                    },
                    sequence: 2,
                    action: InputAction::Key {
                        code: 4,
                        down: true
                    }
                })
                .is_err()
        );
        drop(input);
        drop(runtime);
        assert!(!pressed(&observer, a)?);
        observer.stream().begin()?;
        observer.destroy_window(window)?.check()?;
        Ok(())
    }
}
