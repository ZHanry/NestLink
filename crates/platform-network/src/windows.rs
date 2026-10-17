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
