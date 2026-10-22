#![allow(unsafe_code)]
//! IP Helper subscriptions, with synchronous callback cancellation before free.
use super::*;
use std::ffi::c_void;
use windows_sys::Win32::{
    Foundation::HANDLE,
    NetworkManagement::IpHelper::*,
    Networking::WinSock::AF_UNSPEC,
    System::{SystemInformation::GetTickCount64, WindowsProgramming::QueryUnbiasedInterruptTime},
};

pub(super) fn path_interfaces() -> io::Result<Vec<super::path::NetworkInterface>> {
    use std::collections::BTreeMap;
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    let mut defaults = BTreeMap::<u32, u32>::new();
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: IP Helper allocates a bounded routing table; it is read before
    // FreeMibTable and no pointer escapes. Route existence is evidence of a
    // configured default, not a claim of Internet reachability.
    let result = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    if !table.is_null() {
        unsafe {
            let count = (*table).NumEntries as usize;
            if count <= 65_536 {
                for row in std::slice::from_raw_parts((*table).Table.as_ptr(), count) {
                    if row.DestinationPrefix.PrefixLength == 0 && row.ValidLifetime != 0 {
                        defaults
                            .entry(row.InterfaceIndex)
                            .and_modify(|value| *value = (*value).min(row.Metric))
                            .or_insert(row.Metric);
                    }
                }
            }
            FreeMibTable(table.cast());
        }
    }
    let mut interfaces = BTreeMap::new();
    for address in if_addrs::get_if_addrs()? {
        let Some(index) = address.index else {
            continue;
        };
        let ip = address.ip();
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || address.is_link_local() {
            continue;
        }
        let mut row = MIB_IF_ROW2 {
            InterfaceIndex: index,
            ..Default::default()
        };
        // SAFETY: initialized row with a kernel-provided interface index. The
        // system copies data into the local ABI-sized row without retaining it.
        let result = unsafe { GetIfEntry2(&mut row) };
        if result != 0 {
            continue;
        }
        let mut route = MIB_IPINTERFACE_ROW {
            Family: AF_INET,
            InterfaceIndex: index,
            ..Default::default()
        };
        let metric = if unsafe { GetIpInterfaceEntry(&mut route) } == 0 {
            route.Metric
        } else {
            u32::MAX
        };
        let interface = interfaces
            .entry(index)
            .or_insert_with(|| super::path::NetworkInterface {
                index,
                // SAFETY: NET_LUID's integral Value covers its complete union.
                luid: unsafe { row.InterfaceLuid.Value },
                name: address.name.clone(),
                physical: row.InterfaceAndOperStatusFlags._bitfield & 1 != 0,
                up: row.OperStatus == 1,
                metric: metric.saturating_add(defaults.get(&index).copied().unwrap_or(0)),
                default_route: defaults.contains_key(&index),
                addresses: Vec::new(),
            });
        if !interface.addresses.contains(&ip) {
            interface.addresses.push(ip);
        }
    }
    Ok(interfaces.into_values().collect())
}

pub(super) fn configure_media_datagrams(socket: &socket2::Socket) -> io::Result<()> {
    use std::{mem::size_of, os::windows::io::AsRawSocket};
    use windows_sys::Win32::Networking::WinSock::{SIO_UDP_CONNRESET, WSAGetLastError, WSAIoctl};
    // One closed ICE destination must not terminate reception for every other
    // candidate on the same UDP socket. Windows otherwise delivers its ICMP
    // Port Unreachable as WSAECONNRESET to an unrelated later recv_from.
    let enabled: i32 = 0;
    let mut returned = 0;
    // SAFETY: synchronous documented BOOL input; live owned socket, no output
    // buffer or overlapped operation, and no pointer retained after this call.
    let result = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            (&enabled as *const i32).cast(),
            size_of::<i32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}

pub(super) fn bind_media_interface(
    socket: &socket2::Socket,
    index: u32,
    ipv6: bool,
) -> io::Result<()> {
    use std::{mem::size_of, os::windows::io::AsRawSocket};
    use windows_sys::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, WSAGetLastError, getsockopt,
        setsockopt,
    };
    let (level, option, value) = if ipv6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    } else {
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    };
    // SAFETY: documented DWORD option ABI; IPv4 uses network byte order, IPv6
    // host order. The socket remains owned, live and unbound on this thread.
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            option,
            (&value as *const u32).cast(),
            size_of::<u32>() as i32,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    let mut actual = 0u32;
    let mut size = size_of::<u32>() as i32;
    // SAFETY: initialized output and exact size; verify the option on the same
    // socket subsequently retained for discovery, checks and media traffic.
    let result = unsafe {
        getsockopt(
            socket.as_raw_socket() as usize,
            level,
            option,
            (&mut actual as *mut u32).cast(),
            &mut size,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    // Winsock accepts the IPv4 set value in network order but returns the
    // interface index in host order from getsockopt (IPv6 uses host order for
    // both). Verify the documented readback rather than comparing raw bytes.
    if size != size_of::<u32>() as i32 || actual != index {
        return Err(io::Error::other(format!(
            "media interface option did not persist (index={index}, requested={value:#x}, actual={actual:#x}, bytes={size})"
        )));
    }
    Ok(())
}
pub(super) struct Registration {
    handles: Vec<isize>,
    context: Option<Box<watch::Sender<NetworkState>>>,
}
impl Registration {
    pub fn new(sender: watch::Sender<NetworkState>) -> io::Result<Self> {
        let context = Box::new(sender);
        let pointer = (&*context as *const watch::Sender<NetworkState>).cast::<c_void>();
        let mut registration = Self {
            handles: vec![],
            context: Some(context),
        };
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: stable boxed sender lives until all subscriptions have been
        // cancelled. AF_UNSPEC subscribes both families; rows are never read.
        let result =
            unsafe { NotifyRouteChange2(AF_UNSPEC, Some(route), pointer, false, &mut handle) };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        registration.handles.push(handle as isize);
        // SAFETY: same owned context and valid out pointer; partial setup is
        // cancelled by Registration::drop on any subsequent registration error.
        let result = unsafe {
            NotifyUnicastIpAddressChange(AF_UNSPEC, Some(address), pointer, false, &mut handle)
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        registration.handles.push(handle as isize);
        // SAFETY: stable context, matching system callback ABI and owned handle.
        let result = unsafe {
            NotifyIpInterfaceChange(AF_UNSPEC, Some(interface), pointer, false, &mut handle)
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        registration.handles.push(handle as isize);
        Ok(registration)
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        let mut cancelled = true;
        for handle in self.handles.drain(..) {
            // SAFETY: each handle was returned by an IP Helper subscription.
            // Called outside a callback; successful cancellation waits for its
            // pending callbacks before the boxed context is freed.
            if unsafe { CancelMibChangeNotify2(handle as HANDLE) } != 0 {
                cancelled = false;
            }
        }
        if !cancelled && let Some(context) = self.context.take() {
            // A failed cancellation cannot establish callback quiescence. Keep
            // its tiny context alive rather than permit a use-after-free.
            let _ = Box::leak(context);
        }
    }
}
unsafe fn notify(context: *const c_void, reason: Reason) {
    if context.is_null() {
        return;
    }
    // SAFETY: IP Helper receives exactly the stable boxed sender registered
    // above; cancellation completes before its normal drop.
    let sender = unsafe { &*context.cast::<watch::Sender<NetworkState>>() };
    changed(sender, reason);
}
unsafe extern "system" fn route(
    context: *const c_void,
    _: *const MIB_IPFORWARD_ROW2,
    _: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: forwarded unchanged from this registration's system callback.
    unsafe {
        notify(context, Reason::Route);
    }
}
unsafe extern "system" fn address(
    context: *const c_void,
    _: *const MIB_UNICASTIPADDRESS_ROW,
    _: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: forwarded unchanged from this registration's system callback.
    unsafe {
        notify(context, Reason::Address);
    }
}
unsafe extern "system" fn interface(
    context: *const c_void,
    _: *const MIB_IPINTERFACE_ROW,
    _: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: forwarded unchanged from this registration's system callback.
    unsafe {
        notify(context, Reason::Interface);
    }
}
pub(super) fn clocks() -> io::Result<(u64, u64)> {
    let mut unbiased = 0;
    // SAFETY: initialized writable u64 out parameter. QueryUnbiasedInterruptTime
    // excludes suspend; GetTickCount64 has no pointer inputs and includes it.
    if unsafe { QueryUnbiasedInterruptTime(&mut unbiased) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: no inputs or retained references; result is system uptime in ms.
    Ok((unsafe { GetTickCount64() }, unbiased / 10_000))
}
pub(super) async fn run(sender: watch::Sender<NetworkState>, clocks_before_spawn: (u64, u64)) {
    let mut detector = ResumeDetector {
        previous: Some(clocks_before_spawn),
    };
    let mut tick = tokio::time::interval(SAMPLE_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        match clocks().and_then(|(a, b)| detector.sample(a, b)) {
            Ok(true) => changed(&sender, Reason::Resumed),
            Ok(false) => {}
            Err(_) => {
                changed(&sender, Reason::Unavailable);
                break;
            }
        }
    }
}
