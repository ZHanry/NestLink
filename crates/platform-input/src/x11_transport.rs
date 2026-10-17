//! Bounded authenticated local X11 transport shared by input and image reads.
#![allow(unsafe_code)]
use crate::denied;
use std::{
    io::{self, IoSlice},
    mem::{offset_of, size_of},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    sync::Mutex,
    time::{Duration, Instant},
};
use x11rb::{
    rust_connection::{DefaultStream, PollMode, RustConnection, Stream},
    utils::RawFdContainer,
};
use x11rb_protocol::xauth;
pub(crate) const IO_BUDGET: Duration = Duration::from_millis(150);
pub(crate) const MESSAGE_BYTES: usize = 256 * 1024;
pub(crate) struct Wire {
    pub(crate) setup: bool,
    pub(crate) header: [u8; 32],
    pub(crate) used: usize,
    pub(crate) body: usize,
}
impl Wire {
    pub(crate) fn observe(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.body > 0 {
                let n = self.body.min(bytes.len());
                self.body -= n;
                bytes = &bytes[n..];
                continue;
            }
            let size = if self.setup { 8 } else { 32 };
            let n = (size - self.used).min(bytes.len());
            self.header[self.used..self.used + n].copy_from_slice(&bytes[..n]);
            self.used += n;
            bytes = &bytes[n..];
            if self.used < size {
                continue;
            }
            let words = if self.setup {
                usize::from(u16::from_le_bytes([self.header[6], self.header[7]]))
            } else if self.header[0] & 0x7f == 1 || self.header[0] & 0x7f == 35 {
                u32::from_le_bytes(self.header[4..8].try_into().map_err(io::Error::other)?) as usize
            } else {
                0
            };
            let body = words
                .checked_mul(4)
                .filter(|n| *n <= MESSAGE_BYTES - size)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "X11 reply exceeds message budget",
                    )
                })?;
            self.body = body;
            self.used = 0;
            self.setup = false;
        }
        Ok(())
    }
}
struct Budget {
    until: Instant,
    broken: bool,
    received: usize,
    sent: usize,
    wire: Wire,
}
pub(crate) struct BoundedStream {
    raw: DefaultStream,
    budget: Mutex<Budget>,
}
impl BoundedStream {
    #[cfg(test)]
    pub(crate) fn new(raw: DefaultStream) -> Self {
        Self::with_deadline(raw, Instant::now() + IO_BUDGET)
    }
    fn with_deadline(raw: DefaultStream, until: Instant) -> Self {
        Self {
            raw,
            budget: Mutex::new(Budget {
                until,
                broken: false,
                received: 0,
                sent: 0,
                wire: Wire {
                    setup: true,
                    header: [0; 32],
                    used: 0,
                    body: 0,
                },
            }),
        }
    }
    pub(crate) fn begin(&self) -> io::Result<()> {
        self.begin_until(Instant::now() + IO_BUDGET)
    }
    pub(crate) fn begin_until(&self, until: Instant) -> io::Result<()> {
        let mut b = self
            .budget
            .lock()
            .map_err(|_| io::Error::other("X11 budget poisoned"))?;
        if b.broken {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "X11 connection is terminal",
            ));
        }
        b.until = until;
        b.received = 0;
        b.sent = 0;
        Ok(())
    }
    pub(crate) fn remaining(&self) -> io::Result<Duration> {
        let b = self
            .budget
            .lock()
            .map_err(|_| io::Error::other("X11 budget poisoned"))?;
        if b.broken {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "X11 connection is terminal",
            ));
        }
        b.until
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "X11 operation budget exhausted")
            })
    }
    pub(crate) fn terminate(&self) {
        if let Ok(mut b) = self.budget.lock() {
            b.broken = true;
        } // SAFETY: owned stream retains the same descriptor; shutdown never transfers ownership.
        unsafe {
            libc::shutdown(self.raw.as_raw_fd(), libc::SHUT_RDWR);
        }
    }
    fn result<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if matches!(&result,Err(e) if e.kind()!=io::ErrorKind::WouldBlock) {
            self.terminate();
        }
        result
    }
}
impl Stream for BoundedStream {
    fn poll(&self, mode: PollMode) -> io::Result<()> {
        let result = (|| {
            loop {
                let remaining = self.remaining()?;
                let mut fd = libc::pollfd {
                    fd: self.raw.as_raw_fd(),
                    events: if mode.readable() { libc::POLLIN } else { 0 }
                        | if mode.writable() { libc::POLLOUT } else { 0 },
                    revents: 0,
                };
                // SAFETY: one valid pollfd referencing this owned nonblocking descriptor; finite timeout.
                let ready =
                    unsafe { libc::poll(&mut fd, 1, remaining.as_millis().clamp(1, 150) as i32) };
                if ready > 0 {
                    return Ok(());
                }
                if ready == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "X11 server did not respond",
                    ));
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        })();
        self.result(result)
    }
    fn read(&self, buf: &mut [u8], fds: &mut Vec<RawFdContainer>) -> io::Result<usize> {
        let result = (|| {
            self.remaining()?;
            let n = self.raw.read(buf, fds)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "X11 server closed",
                ));
            }
            if !fds.is_empty() {
                fds.clear();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected X11 descriptors",
                ));
            }
            let mut b = self
                .budget
                .lock()
                .map_err(|_| io::Error::other("X11 budget poisoned"))?;
            b.received = b
                .received
                .checked_add(n)
                .filter(|n| *n <= MESSAGE_BYTES * 2)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "X11 operation read budget exceeded",
                    )
                })?;
            b.wire.observe(&buf[..n])?;
            Ok(n)
        })();
        self.result(result)
    }
    fn write(&self, buf: &[u8], fds: &mut Vec<RawFdContainer>) -> io::Result<usize> {
        let result = (|| {
            self.remaining()?;
            if !fds.is_empty() || buf.len() > MESSAGE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unexpected X11 request budget",
                ));
            }
            let n = self.raw.write(buf, fds)?;
            let mut b = self
                .budget
                .lock()
                .map_err(|_| io::Error::other("X11 budget poisoned"))?;
            b.sent = b
                .sent
                .checked_add(n)
                .filter(|n| *n <= MESSAGE_BYTES * 2)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "X11 operation write budget exceeded",
                    )
                })?;
            Ok(n)
        })();
        self.result(result)
    }
    fn write_vectored(
        &self,
        bufs: &[IoSlice<'_>],
        fds: &mut Vec<RawFdContainer>,
    ) -> io::Result<usize> {
        for buf in bufs {
            if !buf.is_empty() {
                return self.write(buf, fds);
            }
        }
        Ok(0)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Peer {
    pub(crate) pid: i32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) start: u64,
}
pub(crate) type Conn = RustConnection<BoundedStream>;
pub(crate) fn connect(display: u16, screen: usize) -> io::Result<(Conn, Peer)> {
    connect_until(display, screen, Instant::now() + IO_BUDGET)
}
pub(crate) fn connect_until(
    display: u16,
    screen: usize,
    until: Instant,
) -> io::Result<(Conn, Peer)> {
    let path = format!("/tmp/.X11-unix/X{display}");
    let mut address: libc::sockaddr_un = unsafe {
        // SAFETY: all-zero sockaddr_un is a valid initializer before filling family/path.
        std::mem::zeroed()
    };
    address.sun_family = libc::AF_UNIX as u16;
    if path.len() + 1 > address.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "X11 socket path out of bounds",
        ));
    }
    for (out, byte) in address.sun_path.iter_mut().zip(path.bytes()) {
        *out = byte as libc::c_char;
    }
    // SAFETY: standard Linux Unix stream flags, descriptor transferred exactly once to OwnedFd.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: new successful socket has exactly one owner.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: initialized Unix address with checked path and exact length; fd stays owned.
    let code = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            (offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1) as libc::socklen_t,
        )
    };
    if code < 0
        && !matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EINPROGRESS) | Some(libc::EAGAIN)
        )
    {
        return Err(io::Error::last_os_error());
    }
    let (raw, (family, peer_address)) = DefaultStream::from_unix_stream(UnixStream::from(fd))?;
    let stream = BoundedStream::with_deadline(raw, until);
    stream.poll(PollMode::Writable)?;
    let mut socket_error = 0;
    let mut length = size_of::<i32>() as libc::socklen_t;
    // SAFETY: correctly sized scalar output for SO_ERROR on the live owned socket.
    if unsafe {
        libc::getsockopt(
            stream.raw.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut socket_error as *mut i32).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if socket_error != 0 {
        return Err(io::Error::from_raw_os_error(socket_error));
    }
    let mut credentials: libc::ucred = unsafe {
        // SAFETY: all-zero ucred is initialized before getsockopt writes it.
        std::mem::zeroed()
    };
    length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: correctly sized credentials buffer and live Linux Unix descriptor.
    if unsafe {
        libc::getsockopt(
            stream.raw.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } < 0
        || length as usize != size_of::<libc::ucred>()
        || credentials.pid <= 0
    {
        return Err(denied("X11 peer identity unavailable"));
    }
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", credentials.pid))?;
    if stat.len() > 4096 {
        return Err(denied("X11 peer stat exceeds budget"));
    }
    let tail = stat
        .rsplit_once(") ")
        .ok_or_else(|| denied("X11 peer stat invalid"))?
        .1;
    let start = tail
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| denied("X11 peer start time unavailable"))?
        .parse()
        .map_err(io::Error::other)?;
    let (auth_name, auth_data) = xauth::get_auth(family, &peer_address, display)
        .map_err(io::Error::other)?
        .unwrap_or_default();
    if auth_name.len() > 256 || auth_data.len() > 65536 {
        return Err(denied("X11 auth record exceeds budget"));
    }
    let conn = Conn::connect_to_stream_with_auth_info(stream, screen, auth_name, auth_data)
        .map_err(io::Error::other)?;
    Ok((
        conn,
        Peer {
            pid: credentials.pid,
            uid: credentials.uid,
            gid: credentials.gid,
            start,
        },
    ))
}
