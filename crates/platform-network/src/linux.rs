#![allow(unsafe_code)]
//! Kernel route-netlink multicast, bounded datagrams and suspend-aware clocks.
use super::*;
use std::{
    mem::{size_of, zeroed},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
use tokio::io::unix::AsyncFd;
mod paths;
pub(super) use paths::{bind_media_interface, path_interfaces, validate_media_interface};
#[cfg(test)]
mod path_tests;

fn interface_is_up(socket: &socket2::Socket, name: &str, index: u32) -> io::Result<bool> {
    let name = name.as_bytes();
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Linux interface name",
        ));
    }
    // SAFETY: libc owns the exact Linux ifreq ABI. Zero initialization provides
    // a terminated name and initialized union storage for each documented ioctl.
    let mut request: libc::ifreq = unsafe { zeroed() };
    for (target, source) in request.ifr_name.iter_mut().zip(name) {
        *target = *source as libc::c_char;
    }
    // SAFETY: the socket stays live, request is a writable ABI-sized ifreq, and
    // SIOCGIFINDEX only writes its documented integer field without retaining it.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFINDEX, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful SIOCGIFINDEX initialized this union member.
    if unsafe { request.ifr_ifru.ifru_ifindex } as u32 != index {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "Linux interface name no longer identifies the selected index",
        ));
    }
    // SAFETY: same live socket and exact initialized ifreq; SIOCGIFFLAGS writes
    // the documented short flags member without retaining any pointer.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFFLAGS, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful SIOCGIFFLAGS initialized this union member.
    let flags = i32::from(unsafe { request.ifr_ifru.ifru_flags });
    let required = libc::IFF_UP | libc::IFF_RUNNING;
    Ok(flags & required == required)
}

#[cfg(test)]
fn assert_isolated_test_namespace() -> io::Result<()> {
    let current = std::fs::read_link("/proc/self/ns/net")?;
    let initial = std::fs::read_link("/proc/1/ns/net")?;
    if current == initial {
        return Err(io::Error::other(
            "refusing to change the host network namespace",
        ));
    }
    println!(
        "isolated network namespace: self={}, init={}",
        current.display(),
        initial.display()
    );
    Ok(())
}

pub(super) fn subscribe() -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: fixed documented socket constants; no pointer arguments. The
    // returned descriptor is uniquely owned and CLOEXEC/nonblocking at creation.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: freshly returned descriptor has no other Rust owner.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: sockaddr_nl is a plain integer C layout, including reserved padding.
    let mut address: libc::sockaddr_nl = unsafe { zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    address.nl_groups = (libc::RTMGRP_LINK
        | libc::RTMGRP_IPV4_IFADDR
        | libc::RTMGRP_IPV6_IFADDR
        | libc::RTMGRP_IPV4_ROUTE
        | libc::RTMGRP_IPV6_ROUTE) as u32;
    // SAFETY: exact initialized sockaddr_nl address and size; bind does not retain
    // the pointer. nl_pid=0 lets the kernel assign a unique subscription ID.
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_nl).cast(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this socket is uniquely held by OwnedFd, which moves into AsyncFd.
    // No code duplicates, closes or replaces its descriptor while registered;
    // receive only borrows it, and AsyncFd deregisters before OwnedFd closes it.
    unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)
}
fn receive(fd: &OwnedFd) -> io::Result<Option<Reason>> {
    let mut buffer = [0u8; 16_384];
    // SAFETY: sockaddr_nl contains only integer fields; filled by recvfrom.
    let mut source: libc::sockaddr_nl = unsafe { zeroed() };
    let mut length = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    // SAFETY: writable buffer/source with exact lengths. MSG_TRUNC reports the
    // true datagram size so overflow cannot silently discard network changes.
    let size = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            (&mut source as *mut libc::sockaddr_nl).cast(),
            &mut length,
        )
    };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    if size == 0 || size as usize > buffer.len() {
        return Err(io::Error::other("network notification lost or oversized"));
    }
    // Only kernel-origin multicast is a network fact.
    if length as usize != size_of::<libc::sockaddr_nl>()
        || source.nl_pid != 0
        || source.nl_family != libc::AF_NETLINK as u16
    {
        return Ok(None);
    }
    notifications(&buffer[..size as usize])
}
fn notifications(mut bytes: &[u8]) -> io::Result<Option<Reason>> {
    let mut reason = None;
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(io::Error::other("truncated netlink header"));
        }
        let length = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
        if length < 16 || length > bytes.len() {
            return Err(io::Error::other("invalid netlink length"));
        }
        let next = (length + 3) & !3;
        if next > bytes.len() {
            return Err(io::Error::other("truncated netlink padding"));
        }
        match kind {
            1 | 3 => {} // NLMSG_NOOP / DONE
            2 | 4 => return Err(io::Error::other("network notification loss")),
            16 | 17 => reason = Some(Reason::Interface),
            20 | 21 => reason = Some(Reason::Address),
            24 | 25 => reason = Some(Reason::Route),
            _ => reason = Some(Reason::Interface),
        }
        bytes = &bytes[next..];
    }
    Ok(reason)
}
fn clock(id: libc::clockid_t) -> io::Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: initialized timespec and documented clock IDs, no retained pointer.
    if unsafe { libc::clock_gettime(id, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
        return Err(io::Error::other("invalid system clock"));
    }
    (time.tv_sec as u64)
        .checked_mul(1000)
        .and_then(|s| s.checked_add(time.tv_nsec as u64 / 1_000_000))
        .ok_or_else(|| io::Error::other("system clock overflow"))
}
pub(super) fn clocks() -> io::Result<(u64, u64)> {
    Ok((clock(libc::CLOCK_BOOTTIME)?, clock(libc::CLOCK_MONOTONIC)?))
}
pub(super) async fn run(
    socket: AsyncFd<OwnedFd>,
    sender: watch::Sender<NetworkState>,
    clocks_before_spawn: (u64, u64),
) {
    let mut tick = tokio::time::interval(SAMPLE_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut detector = ResumeDetector {
        previous: Some(clocks_before_spawn),
    };
    loop {
        tokio::select! { biased;
            _=tick.tick()=> {
                match clock(libc::CLOCK_BOOTTIME).and_then(|a| clock(libc::CLOCK_MONOTONIC).and_then(|b| detector.sample(a,b))) {
                    Ok(true)=>changed(&sender, Reason::Resumed),
                    Ok(false)=>{},
                    Err(_)=>{changed(&sender,Reason::Unavailable);break;}
                }
            }
            ready=socket.readable()=> {
                let mut ready=match ready {Ok(r)=>r,Err(_)=>{changed(&sender,Reason::Unavailable);break;}};
                match ready.try_io(|fd| receive(fd.get_ref())) {
                    Ok(Ok(Some(reason)))=>changed(&sender,reason),
                    Ok(Ok(None))|Err(_)=>{},
                    Ok(Err(_))=>{changed(&sender,Reason::Unavailable);break;}
                }
                // Never let a flood of notifications monopolize the runtime.
                tokio::task::yield_now().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// The test changes only a fresh network namespace. Run the compiled test
    /// executable inside `unshare --net`, as root/CAP_NET_ADMIN in that namespace.
    #[tokio::test]
    #[ignore = "requires a fresh isolated network namespace with CAP_NET_ADMIN"]
    async fn actual_isolated_ipv4_ipv6_route_and_link_events() -> io::Result<()> {
        assert_isolated_test_namespace()?;
        let monitor = NetworkMonitor::start()?;
        let mut receiver = monitor.subscribe();
        let operations = [
            vec!["link", "set", "lo", "up"],
            vec!["address", "add", "192.0.2.10/32", "dev", "lo"],
            vec![
                "-6",
                "address",
                "add",
                "2001:db8::10/128",
                "dev",
                "lo",
                "nodad",
            ],
            vec!["route", "add", "198.51.100.0/24", "dev", "lo"],
            vec!["link", "set", "lo", "down"],
        ];
        for operation in operations {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let before = receiver.borrow_and_update().generation;
            let status = std::process::Command::new("ip").args(&operation).status()?;
            if !status.success() {
                return Err(io::Error::other("isolated ip operation failed"));
            }
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    receiver.changed().await.map_err(io::Error::other)?;
                    let state = *receiver.borrow_and_update();
                    if !state.available {
                        return Err(io::Error::other("monitor stopped"));
                    }
                    if state.generation > before {
                        break;
                    }
                }
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(io::Error::other)??;
            println!(
                "isolated kernel notification: {:?}, generation {}",
                operation,
                receiver.borrow().generation
            );
        }
        Ok(())
    }
}
