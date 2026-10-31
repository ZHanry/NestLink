//! One Linux scalar ioctl absent from the selected TUN provider's correct ABI.
//! Device creation, packets, persistence and descriptor lifetime stay in tun-rs.
use rustix::ioctl::{IntegerSetter, Opcode, ioctl, opcode};
use std::{io, os::fd::AsFd};

/// Set the ordinary owner's UID on the caller's original, still-ephemeral TUN.
/// The caller retains the descriptor and verifies the actual kernel UID before
/// journaling its complete identity or making the interface persistent.
pub fn set_owner(device: impl AsFd, uid: u32) -> io::Result<()> {
    if uid == u32::MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid TUN owner UID"));
    }
    // Linux if_tun.h declares _IOW('T', 204, int), but tun.c consumes `arg`
    // itself with make_kuid(current_user_ns(), arg), never an int pointer.
    // tun-rs 2.8.16's user() passes &uid; keep this single ABI correction here.
    const SET_OWNER: Opcode = opcode::write::<core::ffi::c_int>(b'T', 204);
    // SAFETY: SET_OWNER is Linux TUNSETOWNER and requires a scalar UID. The
    // borrowed descriptor remains open for this synchronous call; the kernel
    // validates the device, privilege and UID. There is no userspace pointer.
    unsafe { ioctl(device, IntegerSetter::<SET_OWNER>::new_usize(uid as usize)) }
        .map_err(io::Error::from)
}
