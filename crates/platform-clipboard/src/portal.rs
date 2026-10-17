//! Clipboard portal extension on the original, approved RemoteDesktop session.
//! A supplied connection must be that session's original D-Bus caller. There
//! is no command helper, Xwayland fallback, new bus or replacement session.
#![allow(unsafe_code)]
use crate::{
    Backend, CLIPBOARD_TEXT_BYTES, ClipboardAuthority, ClipboardBinding, ClipboardDevice,
    ClipboardDirection, Context, LocalClipboardApproval, denied, timed_out, validate_text,
};
use futures_util::{FutureExt, StreamExt};
use std::{
    collections::HashMap,
    io,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
    time::Instant,
};
use tokio::runtime::{Handle, Runtime};
use zbus::{
    Connection, Proxy,
    proxy::SignalStream,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};
use zeroize::Zeroizing;

const PORTAL: &str = "org.freedesktop.portal.Desktop";
const ROOT: &str = "/org/freedesktop/portal/desktop";
const CLIPBOARD: &str = "org.freedesktop.portal.Clipboard";
const UTF8: &str = "text/plain;charset=utf-8";
const PLAIN: &str = "text/plain";
type Dict = HashMap<String, OwnedValue>;
fn error(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::other(e)
}

/// Supply facts from the owner of the *same* RemoteDesktop portal session.
/// is_active includes its original logind/portal-owner/Closed monitoring.
/// Cleanup must close that original session and report its real completion.
/// This fact bridge cannot grant or restore clipboard permission.
pub trait PortalSessionFacts: Send + Sync {
    fn is_active(&self) -> bool;
    fn invalidate(&self);
    fn wait_closed_until(&self, until: Instant) -> io::Result<()>;
}
/// Created before Start on the exact portal connection/session. Keep this
/// object inside that original portal owner until Start confirms its grant.
pub struct PreparedPortalClipboard {
    connection: Connection,
    owner: String,
    session: OwnedObjectPath,
    proxy: Option<Proxy<'static>>,
    changes: Option<SignalStream<'static>>,
    transfers: Option<SignalStream<'static>>,
    runtime: Handle,
}
pub struct PortalClipboardGrant {
    prepared: PreparedPortalClipboard,
    facts: Arc<dyn PortalSessionFacts>,
}
impl PreparedPortalClipboard {
    fn proxy(&self) -> io::Result<&Proxy<'static>> {
        self.proxy
            .as_ref()
            .ok_or_else(|| denied("clipboard portal bridge is already closed"))
    }
    pub async fn request_before_start(
        connection: &Connection,
        portal_owner: &str,
        original_session: OwnedObjectPath,
        until: Instant,
    ) -> io::Result<Self> {
        let sender = connection
            .unique_name()
            .ok_or_else(|| denied("clipboard portal caller has no unique bus identity"))?
            .as_str()
            .trim_start_matches(':')
            .replace('.', "_");
        let prefix = format!("/org/freedesktop/portal/desktop/session/{sender}/");
        original_session
            .as_str()
            .strip_prefix(&prefix)
            .filter(|token| {
                !token.is_empty()
                    && token.len() <= 128
                    && token
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
            .ok_or_else(|| denied("clipboard must extend the original caller's portal session"))?;
        if !portal_owner.starts_with(':') || portal_owner.len() > 128 {
            return Err(denied("clipboard portal requires its pinned unique owner"));
        }
        let proxy = Proxy::new(connection, portal_owner.to_owned(), ROOT, CLIPBOARD)
            .await
            .map_err(error)?;
        bounded(until, async {
            let bus = Proxy::new(
                connection,
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
            )
            .await
            .map_err(error)?;
            let actual: String = bus.call("GetNameOwner", &(PORTAL,)).await.map_err(error)?;
            let uid: u32 = bus
                .call("GetConnectionUnixUser", &(portal_owner,))
                .await
                .map_err(error)?;
            // SAFETY: scalar effective-user query, no borrowed memory or ownership.
            if actual != portal_owner || uid != unsafe { libc::geteuid() } {
                return Err(denied(
                    "clipboard portal owner does not match the original desktop user",
                ));
            }
            let version: u32 = proxy.get_property("version").await.map_err(error)?;
            if version < 1 {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "installed portal has no Clipboard interface version 1",
                ));
            }
            Ok(())
        })
        .await?;
        // Subscribe before RequestClipboard/Start so early owner/transfer facts
        // cannot be lost. Signals never trigger an automatic clipboard read.
        let changes = bounded(until, async {
            proxy
                .receive_signal("SelectionOwnerChanged")
                .await
                .map_err(error)
        })
        .await?;
        let transfers = bounded(until, async {
            proxy
                .receive_signal("SelectionTransfer")
                .await
                .map_err(error)
        })
        .await?;
        bounded(until, async {
            proxy
                .call::<_, _, ()>(
                    "RequestClipboard",
                    &(original_session.clone(), HashMap::<&str, Value<'_>>::new()),
                )
                .await
                .map_err(error)
        })
        .await?;
        Ok(Self {
            connection: connection.clone(),
            owner: portal_owner.to_owned(),
            session: original_session,
            proxy: Some(proxy),
            changes: Some(changes),
            transfers: Some(transfers),
            runtime: Handle::try_current().map_err(error)?,
        })
    }
    /// clipboard_enabled must be the boolean from this original session's
    /// successful Start result, never a guessed capability or UI checkbox.
    pub fn finish_start(
        self,
        clipboard_enabled: bool,
        facts: Arc<dyn PortalSessionFacts>,
    ) -> io::Result<PortalClipboardGrant> {
        if !clipboard_enabled {
            return Err(denied(
                "system portal did not grant clipboard access at Start",
            ));
        }
        Ok(PortalClipboardGrant {
            prepared: self,
            facts,
        })
    }
}
impl Drop for PreparedPortalClipboard {
    fn drop(&mut self) {
        // zbus queues RemoveMatch from Proxy/SignalStream destructors. Enter
        // the original runtime even when Start denial or UI drop is synchronous.
        // All bus resources with such destructors are consumed inside this scope.
        let _entered = self.runtime.enter();
        self.changes.take();
        self.transfers.take();
        self.proxy.take();
    }
}
pub struct PortalClipboard;
impl PortalClipboard {
    pub fn open(
        grant: PortalClipboardGrant,
        binding: ClipboardBinding,
        approval: LocalClipboardApproval,
        authority: Arc<dyn ClipboardAuthority>,
    ) -> io::Result<ClipboardDevice> {
        ClipboardDevice::open(binding, approval, authority, move |until| {
            if !grant.facts.is_active() {
                return Err(denied(
                    "original portal session ended before clipboard attachment",
                ));
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let mut backend = Clipboard {
                grant,
                runtime,
                stored: None,
                formats: None,
                owned: false,
                closed: false,
            };
            backend.check(until)?;
            Ok(Box::new(backend))
        })
    }
}
struct Clipboard {
    grant: PortalClipboardGrant,
    runtime: Runtime,
    stored: Option<Zeroizing<String>>,
    formats: Option<Vec<String>>,
    owned: bool,
    closed: bool,
}
async fn bounded<T>(
    until: Instant,
    future: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    if Instant::now() >= until {
        return Err(timed_out("clipboard portal budget expired before dispatch"));
    }
    tokio::time::timeout_at(tokio::time::Instant::from_std(until), future)
        .await
        .map_err(|_| timed_out("clipboard portal call exceeded its original deadline"))?
}
fn nonblocking(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: fd remains owned throughout the flag query/update. Other flags are preserved.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn wait_fd(
    fd: &OwnedFd,
    writable: bool,
    context: &Context,
    direction: ClipboardDirection,
    until: Instant,
) -> io::Result<()> {
    loop {
        context.check(direction, until)?;
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: if writable {
                libc::POLLOUT
            } else {
                libc::POLLIN
            },
            revents: 0,
        };
        // SAFETY: one live owned descriptor, exact pollfd count, finite cancellation-aware wait.
        let result = unsafe {
            libc::poll(
                &mut poll,
                1,
                until
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .clamp(1, 5) as i32,
            )
        };
        if result > 0 {
            if poll.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "portal supplied an invalid clipboard descriptor",
                ));
            }
            return Ok(());
        }
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}
fn read_fd(fd: OwnedFd, context: &Context, until: Instant) -> io::Result<Zeroizing<String>> {
    nonblocking(&fd)?;
    let mut bytes = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0u8; 4096]);
    loop {
        wait_fd(&fd, false, context, ClipboardDirection::Read, until)?;
        // SAFETY: writable fixed buffer and borrowed valid descriptor; read cannot exceed its length.
        let count = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if count == 0 {
            break;
        }
        if count < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(error);
        }
        let count = count as usize;
        if bytes.len() + count > CLIPBOARD_TEXT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "portal clipboard exceeds bounded UTF-8 budget",
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    context.check(ClipboardDirection::Read, until)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "portal clipboard contains invalid UTF-8",
        )
    })?;
    validate_text(text)?;
    Ok(Zeroizing::new(text.to_owned()))
}
fn write_fd(fd: OwnedFd, text: &str, context: &Context, until: Instant) -> io::Result<()> {
    nonblocking(&fd)?;
    let mut offset = 0;
    while offset < text.len() {
        wait_fd(&fd, true, context, ClipboardDirection::Write, until)?;
        let bytes = &text.as_bytes()[offset..];
        // SAFETY: immutable valid slice and live borrowed descriptor; count is bounded by that slice.
        let count = unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "portal clipboard descriptor accepted no bytes",
            ));
        }
        if count < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(error);
        }
        offset += count as usize;
    }
    context.check(ClipboardDirection::Write, until)
}
impl Clipboard {
    fn changes(&mut self, context: &Context, until: Instant) -> io::Result<()> {
        context.live(until)?;
        for _ in 0..64 {
            match self
                .grant
                .prepared
                .changes
                .as_mut()
                .ok_or_else(|| denied("portal owner stream is already closed"))?
                .next()
                .now_or_never()
            {
                Some(Some(signal)) => {
                    let (session, mut facts): (OwnedObjectPath, Dict) =
                        signal.body().deserialize().map_err(error)?;
                    if session != self.grant.prepared.session {
                        continue;
                    }
                    let formats: Vec<String> = facts
                        .remove("mime_types")
                        .ok_or_else(|| denied("portal clipboard change omitted its MIME formats"))?
                        .try_into()
                        .map_err(error)?;
                    if formats.len() > 64 || formats.iter().any(|value| value.len() > 256) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "portal clipboard MIME inventory exceeds budget",
                        ));
                    }
                    let owned: bool = facts
                        .remove("session_is_owner")
                        .ok_or_else(|| denied("portal clipboard change omitted ownership facts"))?
                        .try_into()
                        .map_err(error)?;
                    self.formats = Some(formats);
                    self.owned = owned;
                    if !owned {
                        self.stored.take();
                    }
                }
                Some(None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "portal clipboard change stream ended",
                    ));
                }
                None => return Ok(()),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "portal clipboard owner event budget exceeded",
        ))
    }
    fn owner_check(&self, until: Instant) -> io::Result<()> {
        if self.closed || !self.grant.facts.is_active() {
            return Err(denied(
                "original Wayland clipboard portal session is terminal",
            ));
        }
        self.runtime.block_on(bounded(until, async {
            let bus = Proxy::new(
                &self.grant.prepared.connection,
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
            )
            .await
            .map_err(error)?;
            let actual: String = bus.call("GetNameOwner", &(PORTAL,)).await.map_err(error)?;
            if actual != self.grant.prepared.owner {
                return Err(denied("original Wayland clipboard portal owner changed"));
            }
            Ok(())
        }))
    }
    fn transfer(
        &mut self,
        mime: String,
        serial: u32,
        context: &Context,
        until: Instant,
    ) -> io::Result<()> {
        let result = (|| {
            self.owner_check(until)?;
            context.check(ClipboardDirection::Write, until)?;
            if ![UTF8, PLAIN].contains(&mime.as_str()) || !self.owned {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "portal requested an unadvertised clipboard format",
                ));
            }
            let text = self
                .stored
                .as_ref()
                .ok_or_else(|| denied("portal clipboard text was already discarded"))?;
            let fd: zbus::zvariant::OwnedFd = self.runtime.block_on(bounded(until, async {
                self.grant
                    .prepared
                    .proxy()?
                    .call(
                        "SelectionWrite",
                        &(self.grant.prepared.session.clone(), serial),
                    )
                    .await
                    .map_err(error)
            }))?;
            write_fd(fd.into(), text, context, until)?;
            self.owner_check(until)?;
            context.check(ClipboardDirection::Write, until)
        })();
        let successful = result.is_ok();
        // Completion acknowledges an actual completed bounded FD write. A
        // cancellation/format failure is never reported as a successful paste.
        let done = self.runtime.block_on(bounded(until, async {
            self.grant
                .prepared
                .proxy()?
                .call::<_, _, ()>(
                    "SelectionWriteDone",
                    &(self.grant.prepared.session.clone(), serial, successful),
                )
                .await
                .map_err(error)
        }));
        result.and(done)
    }
}
impl Backend for Clipboard {
    fn check(&mut self, until: Instant) -> io::Result<()> {
        self.owner_check(until)
    }
    fn read(&mut self, context: &Context, until: Instant) -> io::Result<Option<Zeroizing<String>>> {
        self.service(context, until)?;
        self.owner_check(until)?;
        context.check(ClipboardDirection::Read, until)?;
        let mime = match &self.formats {
            Some(formats) if formats.iter().any(|value| value == UTF8) => UTF8,
            Some(formats) if formats.iter().any(|value| value == PLAIN) => PLAIN,
            Some(_) => return Ok(None),
            None => UTF8,
        };
        let fd: zbus::zvariant::OwnedFd = self.runtime.block_on(bounded(until, async {
            self.grant
                .prepared
                .proxy()?
                .call(
                    "SelectionRead",
                    &(self.grant.prepared.session.clone(), mime),
                )
                .await
                .map_err(error)
        }))?;
        let text = read_fd(fd.into(), context, until)?;
        self.owner_check(until)?;
        context.check(ClipboardDirection::Read, until)?;
        Ok(Some(text))
    }
    fn write(&mut self, text: &str, context: &Context, until: Instant) -> io::Result<()> {
        validate_text(text)?;
        self.changes(context, until)?;
        self.owner_check(until)?;
        context.check(ClipboardDirection::Write, until)?;
        let pending = Zeroizing::new(text.to_owned());
        let result = self.runtime.block_on(bounded(until, async {
            self.grant
                .prepared
                .proxy()?
                .call::<_, _, ()>(
                    "SetSelection",
                    &(
                        self.grant.prepared.session.clone(),
                        HashMap::from([("mime_types", Value::from(vec![UTF8, PLAIN]))]),
                    ),
                )
                .await
                .map_err(error)
        }));
        if result.is_err() {
            self.stored.take();
        }
        result?;
        self.owned = true;
        self.formats = Some(vec![UTF8.to_owned(), PLAIN.to_owned()]);
        // A pre-commit owner signal may precede the new-owner signal. Drain
        // those facts before attaching this new value, so old metadata cannot
        // discard it and accidentally leave an advertised empty selection.
        self.changes(context, until)?;
        if self.owned {
            self.stored = Some(pending);
        }
        self.owner_check(until)?;
        context.check(ClipboardDirection::Write, until)
    }
    fn service(&mut self, context: &Context, until: Instant) -> io::Result<()> {
        context.live(until)?;
        self.changes(context, until)?;
        for _ in 0..64 {
            match self
                .grant
                .prepared
                .transfers
                .as_mut()
                .ok_or_else(|| denied("portal transfer stream is already closed"))?
                .next()
                .now_or_never()
            {
                Some(Some(signal)) => {
                    let (session, mime, serial): (OwnedObjectPath, String, u32) =
                        signal.body().deserialize().map_err(error)?;
                    if session == self.grant.prepared.session {
                        self.transfer(mime, serial, context, until)?;
                    }
                }
                Some(None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "portal clipboard transfer stream ended",
                    ));
                }
                None => return Ok(()),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "portal clipboard transfer event budget exceeded",
        ))
    }
    fn close(&mut self, until: Instant) -> io::Result<()> {
        self.stored.take();
        self.owned = false;
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // Clipboard is an extension of this same session. Closing the original
        // session withdraws only its ownership; SetSelection on a newer owner's
        // content would incorrectly overwrite that user's clipboard.
        self.grant.facts.invalidate();
        self.grant.facts.wait_closed_until(until)
    }
}
#[cfg(test)]
mod tests;
