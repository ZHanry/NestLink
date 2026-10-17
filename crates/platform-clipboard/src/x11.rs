//! ICCCM CLIPBOARD text selections, with bounded INCR reads. PRIMARY and the
//! user's prior content are never read at startup or saved for restoration.
#![allow(unsafe_code)]
use crate::{
    Backend, CLIPBOARD_TEXT_BYTES, ClipboardAuthority, ClipboardBinding, ClipboardDevice,
    ClipboardDirection, Context, LocalClipboardApproval, denied, timed_out, validate_text,
    x11_transport::{Conn, Peer, connect_until, connect_until_auth},
};
use nestlink_platform_session::LinuxDesktopSession;
use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use x11rb::{
    COPY_DEPTH_FROM_PARENT, CURRENT_TIME, NONE,
    connection::Connection,
    protocol::{
        Event,
        xfixes::{self, ConnectionExt as _},
        xproto::{self, ConnectionExt as _},
    },
    wrapper::ConnectionExt as _,
};
use zeroize::Zeroizing;

fn error(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::other(e)
}
fn atom(conn: &Conn, name: &[u8]) -> io::Result<u32> {
    Ok(conn
        .intern_atom(false, name)
        .map_err(error)?
        .reply()
        .map_err(error)?
        .atom)
}
struct Atoms {
    clipboard: u32,
    utf8: u32,
    plain: u32,
    targets: u32,
    timestamp: u32,
    incr: u32,
    property: u32,
}
pub struct X11Clipboard;
impl X11Clipboard {
    /// display and PID must come from the local GUI/authenticated IPC peer.
    /// A remote address or arbitrary fallback DISPLAY is never accepted.
    pub fn open_for_desktop(
        display: &str,
        local_gui_pid: u32,
        binding: ClipboardBinding,
        approval: LocalClipboardApproval,
        authority: Arc<dyn ClipboardAuthority>,
    ) -> io::Result<ClipboardDevice> {
        let display = display.to_owned();
        ClipboardDevice::open(binding, approval, authority, move |until| {
            let session = LinuxDesktopSession::open(local_gui_pid, &display)?;
            Ok(Box::new(Clipboard::open(&display, Some(session), until)?))
        })
    }
}
struct Clipboard {
    session: Option<LinuxDesktopSession>,
    conn: Conn,
    _peer: Peer,
    window: u32,
    atoms: Atoms,
    stored: Option<Zeroizing<String>>,
    owned: bool,
    timestamp: u32,
    closed: bool,
}
impl Clipboard {
    fn open(
        display: &str,
        session: Option<LinuxDesktopSession>,
        until: Instant,
    ) -> io::Result<Self> {
        Self::open_with_auth(display, session, until, None)
    }
    fn open_with_auth(
        display: &str,
        session: Option<LinuxDesktopSession>,
        until: Instant,
        auth: Option<(Vec<u8>, Vec<u8>)>,
    ) -> io::Result<Self> {
        let parsed = x11rb_protocol::parse_display::parse_display(Some(display)).map_err(error)?;
        if display.len() > 32
            || !display.starts_with(':')
            || !parsed.host.is_empty()
            || parsed.protocol.is_some()
        {
            return Err(denied(
                "clipboard requires an explicit local Unix X11 display",
            ));
        }
        let (conn, peer) = match auth {
            Some(auth) => connect_until_auth(
                parsed.display,
                usize::from(parsed.screen),
                until,
                Some(auth),
            )?,
            None => connect_until(parsed.display, usize::from(parsed.screen), until)?,
        };
        // SAFETY: scalar current-user query, no memory or ownership involved.
        let uid = unsafe { libc::geteuid() };
        if (peer.uid != uid && peer.uid != 0) || peer.pid <= 0 || peer.start == 0 {
            return Err(denied("X11 clipboard server belongs to another user"));
        }
        let root = conn
            .setup()
            .roots
            .get(usize::from(parsed.screen))
            .ok_or_else(|| denied("X11 clipboard screen is absent"))?
            .root;
        let fixes = conn
            .xfixes_query_version(2, 0)
            .map_err(error)?
            .reply()
            .map_err(error)?;
        if fixes.major_version < 2 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "X11 clipboard requires XFixes selection notifications",
            ));
        }
        let window = conn.generate_id().map_err(error)?;
        conn.create_window(
            COPY_DEPTH_FROM_PARENT,
            window,
            root,
            0,
            0,
            1,
            1,
            0,
            xproto::WindowClass::INPUT_ONLY,
            0,
            &xproto::CreateWindowAux::new().event_mask(
                xproto::EventMask::PROPERTY_CHANGE | xproto::EventMask::STRUCTURE_NOTIFY,
            ),
        )
        .map_err(error)?
        .check()
        .map_err(error)?;
        let atoms = Atoms {
            clipboard: atom(&conn, b"CLIPBOARD")?,
            utf8: atom(&conn, b"UTF8_STRING")?,
            plain: atom(&conn, b"text/plain;charset=utf-8")?,
            targets: atom(&conn, b"TARGETS")?,
            timestamp: atom(&conn, b"TIMESTAMP")?,
            incr: atom(&conn, b"INCR")?,
            property: atom(&conn, b"_NESTLINK_TEXT_CLIPBOARD")?,
        };
        conn.xfixes_select_selection_input(
            window,
            atoms.clipboard,
            xfixes::SelectionEventMask::SET_SELECTION_OWNER
                | xfixes::SelectionEventMask::SELECTION_WINDOW_DESTROY
                | xfixes::SelectionEventMask::SELECTION_CLIENT_CLOSE,
        )
        .map_err(error)?
        .check()
        .map_err(error)?;
        let clipboard = Self {
            session,
            conn,
            _peer: peer,
            window,
            atoms,
            stored: None,
            owned: false,
            timestamp: 0,
            closed: false,
        };
        Ok(clipboard)
    }
    fn begin(&self, until: Instant) -> io::Result<()> {
        if self.closed || Instant::now() >= until {
            return Err(timed_out("X11 clipboard operation is terminal or expired"));
        }
        self.conn.stream().begin_until(until)
    }
    fn owner(&self) -> io::Result<u32> {
        Ok(self
            .conn
            .get_selection_owner(self.atoms.clipboard)
            .map_err(error)?
            .reply()
            .map_err(error)?
            .owner)
    }
    fn convert_request(
        &mut self,
        request: xproto::SelectionRequestEvent,
        context: &Context,
        until: Instant,
    ) -> io::Result<()> {
        let property = if request.property == NONE {
            request.target
        } else {
            request.property
        };
        let mut selected = NONE;
        if request.selection == self.atoms.clipboard && request.owner == self.window && self.owned {
            context.check(ClipboardDirection::Write, until)?;
            if request.target == self.atoms.targets {
                self.conn
                    .change_property32(
                        xproto::PropMode::REPLACE,
                        request.requestor,
                        property,
                        xproto::AtomEnum::ATOM,
                        &[
                            self.atoms.targets,
                            self.atoms.timestamp,
                            self.atoms.utf8,
                            self.atoms.plain,
                        ],
                    )
                    .map_err(error)?
                    .check()
                    .map_err(error)?;
                selected = property;
            } else if request.target == self.atoms.timestamp {
                self.conn
                    .change_property32(
                        xproto::PropMode::REPLACE,
                        request.requestor,
                        property,
                        xproto::AtomEnum::INTEGER,
                        &[self.timestamp],
                    )
                    .map_err(error)?
                    .check()
                    .map_err(error)?;
                selected = property;
            } else if (request.target == self.atoms.utf8 || request.target == self.atoms.plain)
                && let Some(text) = &self.stored
            {
                context.check(ClipboardDirection::Write, until)?;
                self.conn
                    .change_property8(
                        xproto::PropMode::REPLACE,
                        request.requestor,
                        property,
                        request.target,
                        text.as_bytes(),
                    )
                    .map_err(error)?
                    .check()
                    .map_err(error)?;
                context.check(ClipboardDirection::Write, until)?;
                selected = property;
            }
        }
        self.conn
            .send_event(
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
                    property: selected,
                },
            )
            .map_err(error)?
            .check()
            .map_err(error)?;
        self.conn.flush().map_err(error)
    }
    fn event(&mut self, event: Event, context: &Context, until: Instant) -> io::Result<()> {
        match event {
            Event::SelectionRequest(request) => self.convert_request(request, context, until),
            Event::SelectionClear(event)
                if event.owner == self.window && event.selection == self.atoms.clipboard =>
            {
                self.owned = false;
                self.stored.take();
                Ok(())
            }
            Event::XfixesSelectionNotify(event) if event.selection == self.atoms.clipboard => {
                self.owned = event.owner == self.window;
                if !self.owned {
                    self.stored.take();
                }
                Ok(())
            }
            Event::DestroyNotify(event) if event.window == self.window => {
                Err(denied("X11 clipboard selection window disappeared"))
            }
            _ => Ok(()),
        }
    }
    fn next_event(&mut self, context: &Context, until: Instant) -> io::Result<Event> {
        loop {
            context.live(until)?;
            if let Some(event) = self.conn.poll_for_event().map_err(error)? {
                return Ok(event);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn server_time(&mut self, context: &Context, until: Instant) -> io::Result<u32> {
        self.conn
            .change_property8(
                xproto::PropMode::REPLACE,
                self.window,
                self.atoms.property,
                self.atoms.utf8,
                b"",
            )
            .map_err(error)?
            .check()
            .map_err(error)?;
        self.conn.flush().map_err(error)?;
        for _ in 0..128 {
            let event = self.next_event(context, until)?;
            if let Event::PropertyNotify(event) = &event
                && event.window == self.window
                && event.atom == self.atoms.property
                && event.state == xproto::Property::NEW_VALUE
            {
                if event.time == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "X11 server supplied no selection timestamp",
                    ));
                }
                return Ok(event.time);
            }
            self.event(event, context, until)?;
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "X11 clipboard timestamp event budget exceeded",
        ))
    }
    fn property(&self, target: u32) -> io::Result<xproto::GetPropertyReply> {
        let reply = self
            .conn
            .get_property(
                true,
                self.window,
                self.atoms.property,
                xproto::AtomEnum::ANY,
                0,
                ((CLIPBOARD_TEXT_BYTES + 4) / 4) as u32,
            )
            .map_err(error)?
            .reply()
            .map_err(error)?;
        if reply.bytes_after != 0 || reply.value.len() > CLIPBOARD_TEXT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "X11 clipboard exceeds the bounded UTF-8 text budget",
            ));
        }
        if reply.type_ != self.atoms.incr && (reply.type_ != target || reply.format != 8) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "X11 clipboard is not the requested UTF-8 text format",
            ));
        }
        Ok(reply)
    }
    fn read_target(
        &mut self,
        target: u32,
        context: &Context,
        until: Instant,
    ) -> io::Result<Option<Zeroizing<String>>> {
        self.conn
            .delete_property(self.window, self.atoms.property)
            .map_err(error)?
            .check()
            .map_err(error)?;
        context.check(ClipboardDirection::Read, until)?;
        self.conn
            .convert_selection(
                self.window,
                self.atoms.clipboard,
                target,
                self.atoms.property,
                CURRENT_TIME,
            )
            .map_err(error)?
            .check()
            .map_err(error)?;
        self.conn.flush().map_err(error)?;
        let mut transfer = None;
        for _ in 0..256 {
            let event = self.next_event(context, until)?;
            if let Event::SelectionNotify(event) = &event
                && event.requestor == self.window
                && event.selection == self.atoms.clipboard
                && event.target == target
            {
                if event.property == NONE {
                    return Ok(None);
                }
                if event.property != self.atoms.property {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "X11 selection returned a different property",
                    ));
                }
                transfer = Some(self.property(target)?);
                break;
            }
            self.event(event, context, until)?;
        }
        let first = transfer.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "X11 selection notify event budget exceeded",
            )
        })?;
        let mut bytes = Zeroizing::new(Vec::new());
        if first.type_ == self.atoms.incr {
            if first.format != 32
                || first.value.len() != 4
                || first
                    .value32()
                    .and_then(|mut values| values.next())
                    .is_none_or(|size| size as usize > CLIPBOARD_TEXT_BYTES)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "X11 incremental selection hint exceeds text budget",
                ));
            }
            self.conn.flush().map_err(error)?;
            let mut done = false;
            for _ in 0..512 {
                context.check(ClipboardDirection::Read, until)?;
                let event = self.next_event(context, until)?;
                if let Event::PropertyNotify(event) = &event
                    && event.window == self.window
                    && event.atom == self.atoms.property
                    && event.state == xproto::Property::NEW_VALUE
                {
                    let chunk = self.property(target)?;
                    if chunk.type_ == self.atoms.incr || chunk.format != 8 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "X11 incremental selection changed its format",
                        ));
                    }
                    if chunk.value.is_empty() {
                        done = true;
                        break;
                    }
                    if bytes.len() + chunk.value.len() > CLIPBOARD_TEXT_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "X11 incremental selection exceeds text budget",
                        ));
                    }
                    bytes.extend_from_slice(&chunk.value);
                    self.conn.flush().map_err(error)?;
                } else {
                    self.event(event, context, until)?;
                }
            }
            if !done {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "X11 incremental selection event budget exceeded",
                ));
            }
        } else {
            bytes.extend_from_slice(&first.value);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "X11 clipboard contains invalid UTF-8",
            )
        })?;
        validate_text(text)?;
        context.check(ClipboardDirection::Read, until)?;
        Ok(Some(Zeroizing::new(text.to_owned())))
    }
}
impl Backend for Clipboard {
    fn check(&mut self, until: Instant) -> io::Result<()> {
        self.begin(until)?;
        if let Some(session) = &self.session {
            session.check_until(until)?;
        }
        let owner = self.owner()?;
        self.owned = owner == self.window;
        if !self.owned {
            self.stored.take();
        }
        Ok(())
    }
    fn read(&mut self, context: &Context, until: Instant) -> io::Result<Option<Zeroizing<String>>> {
        self.check(until)?;
        let original = self.owner()?;
        if original == NONE {
            return Ok(None);
        }
        if original == self.window {
            return Ok(self
                .stored
                .as_ref()
                .map(|value| Zeroizing::new(value.to_string())));
        }
        let mut result = self.read_target(self.atoms.utf8, context, until)?;
        if result.is_none() {
            result = self.read_target(self.atoms.plain, context, until)?;
        }
        if self.owner()? != original {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "X11 clipboard owner changed while reading",
            ));
        }
        self.check(until)?;
        Ok(result)
    }
    fn write(&mut self, text: &str, context: &Context, until: Instant) -> io::Result<()> {
        validate_text(text)?;
        self.check(until)?;
        let timestamp = self.server_time(context, until)?;
        context.check(ClipboardDirection::Write, until)?;
        self.stored = Some(Zeroizing::new(text.to_owned()));
        self.conn
            .set_selection_owner(self.window, self.atoms.clipboard, timestamp)
            .map_err(error)?
            .check()
            .map_err(error)?;
        self.conn.flush().map_err(error)?;
        if self.owner()? != self.window {
            self.stored.take();
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "X11 server did not accept clipboard selection ownership",
            ));
        }
        self.owned = true;
        self.timestamp = timestamp;
        context.check(ClipboardDirection::Write, until)
    }
    fn service(&mut self, context: &Context, until: Instant) -> io::Result<()> {
        self.begin(until)?;
        for _ in 0..128 {
            match self.conn.poll_for_event().map_err(error)? {
                Some(event) => self.event(event, context, until)?,
                None => return Ok(()),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "X11 clipboard event budget exceeded",
        ))
    }
    fn close(&mut self, until: Instant) -> io::Result<()> {
        self.stored.take();
        self.owned = false;
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // Destroy only our window; never clear/restore someone else's selection.
        let outcome = (|| {
            self.conn.stream().begin_until(until)?;
            self.conn
                .destroy_window(self.window)
                .map_err(error)?
                .check()
                .map_err(error)?;
            self.conn.flush().map_err(error)
        })();
        self.conn.stream().terminate();
        outcome
    }
}
#[cfg(test)]
mod tests;
