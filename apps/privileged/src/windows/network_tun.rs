//! Windows TUN privilege adapter. The ordinary business owner retains network
//! transport, login and packet policy. This module grants none of those powers.
mod packet_pipe;
mod provider;
pub use packet_pipe::{PacketBinding, PacketPipe, PacketReceipt, PacketServer, ProviderIdentity};
pub use provider::PinnedProviderImage;

use super::{
    local_port_gate::{ProcessIdentity, store},
    security,
};
use std::{fs::File, io, os::windows::io::AsRawHandle, path::Path};

/// Same-handle selected public input, reusing the WFP reparse/type/ACL checks.
/// The caller parses the bounded public plan, then checks its captured SID on
/// this retained descriptor. No pathname is reopened for that ownership check.
pub struct SelectedPlanFile {
    file: File,
}
impl SelectedPlanFile {
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(security::denied());
        }
        Ok(Self {
            file: store::open(path, false, false)?,
        })
    }
    pub fn bytes(&self) -> io::Result<Vec<u8>> {
        store::bounded(self.file.try_clone()?)
    }
    pub fn require_owner(&self, sid: &str) -> io::Result<()> {
        security::private_owner_acl(self.file.as_raw_handle().cast(), sid)
    }
}
pub fn save_owner_plan(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let owner = ProcessIdentity::read(std::process::id())?;
    if !owner.normal() || !path.is_absolute() {
        return Err(security::denied());
    }
    nestlink_platform_security::check_private_directory(
        path.parent().ok_or_else(security::denied)?,
    )?;
    store::save_owner_plan(path, bytes, &owner.sid)
}
