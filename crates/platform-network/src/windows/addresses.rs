//! IP Helper owns unicast validity, including temporary IPv6/DAD lifetimes.
use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::*,
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
};

pub(super) fn preferred() -> io::Result<BTreeSet<(u32, IpAddr)>> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: IP Helper allocates the exact documented table and retains no
    // pointer to this local output. Every successful allocation is freed below.
    let status = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if table.is_null() {
        return Err(io::Error::other("unicast address table unavailable"));
    }
    let mut result = BTreeSet::new();
    // SAFETY: the kernel's allocated rows are read within the count bound and
    // freed synchronously; only copied scalar IP facts leave this function.
    unsafe {
        let count = (*table).NumEntries as usize;
        if count > 65_536 {
            FreeMibTable(table.cast());
            return Err(io::Error::other("unicast address table exceeds bound"));
        }
        for row in std::slice::from_raw_parts((*table).Table.as_ptr(), count) {
            // IP_DAD_STATE::IpDadStatePreferred = 4. A zero preferred lifetime
            // denotes an unusable/deprecated source even before its next event.
            if row.InterfaceIndex == 0
                || row.DadState != 4
                || row.ValidLifetime == 0
                || row.PreferredLifetime == 0
            {
                continue;
            }
            let ip: IpAddr = match row.Address.si_family {
                AF_INET => {
                    Ipv4Addr::from(row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into()
                }
                AF_INET6 => Ipv6Addr::from(row.Address.Ipv6.sin6_addr.u.Byte).into(),
                _ => continue,
            };
            result.insert((row.InterfaceIndex, ip));
        }
        FreeMibTable(table.cast());
    }
    Ok(result)
}
