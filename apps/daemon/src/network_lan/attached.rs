//! Explicit optional LAN adapters on the original managed host packet owner.
//! The TUN helper and signed packet authority remain the existing originals.
use super::{Result, bytes32, policy_bytes};
use crate::network_packet_runtime::{PacketIoFuture, WholePacketDevice};
use nestlink_sdk::network::{lan::{LanBridge, LanPolicy}, packet_access::OnlinePacketAccess};
use std::{io, path::PathBuf, time::{Duration, Instant}};

#[derive(clap::Args)]
pub(crate) struct Options {
    /// Independently reviewed owner-private LAN policy; disabled when omitted.
    #[arg(long, requires = "approve_lan_policy")]
    lan_policy: Option<PathBuf>,
    /// Exact policy SHA256, URL-safe unpadded base64; never inferred from a grant.
    #[arg(long, requires = "lan_policy")]
    approve_lan_policy: Option<String>,
}
pub(crate) struct Reviewed {
    path: PathBuf,
    digest: [u8; 32],
    policy: LanPolicy,
}
pub(crate) struct Attached {
    review: Reviewed,
    bridge: LanBridge,
}
impl Options {
    pub fn prepare(&self, space: &str) -> Result<Option<Reviewed>> {
        let (Some(path), Some(approval)) = (&self.lan_policy, &self.approve_lan_policy) else {
            if self.lan_policy.is_some() || self.approve_lan_policy.is_some() {
                return Err(io::Error::other("LAN policy and independent approval must be supplied together").into());
            }
            return Ok(None);
        };
        let digest = bytes32(approval)?;
        let bytes = policy_bytes(path)?;
        if nestlink_identity::digest(&bytes) != digest {
            return Err(io::Error::other("LAN policy differs from its independent approval").into());
        }
        let policy: LanPolicy = serde_json::from_slice(&bytes)?;
        policy.validate()?;
        policy.check_interface()?;
        if policy.space_id != space {
            return Err(io::Error::other("LAN policy belongs to another pinned space").into());
        }
        Ok(Some(Reviewed { path: path.clone(), digest, policy }))
    }
}
impl Reviewed {
    pub fn bind(self, access: &OnlinePacketAccess) -> Result<Attached> {
        if nestlink_identity::digest(&policy_bytes(&self.path)?) != self.digest {
            return Err(io::Error::other("LAN approval changed before original TUN handoff").into());
        }
        let bridge = LanBridge::bind(self.policy.clone(), &self.policy.space_id, access)?;
        Ok(Attached { review: self, bridge })
    }
}
impl Attached {
    pub fn check(&self) -> Result {
        if nestlink_identity::digest(&policy_bytes(&self.review.path)?) != self.review.digest {
            return Err(io::Error::other("original managed host LAN approval changed").into());
        }
        self.bridge.check_current()?;
        Ok(())
    }
    pub fn shutdown(&self) -> io::Result<()> {
        self.bridge.shutdown(Instant::now() + Duration::from_secs(5))
    }
}
/// Both devices are observed by the same noncloneable packet admission and
/// carrier loop. A reserved discovery envelope cannot reach the OS TUN.
pub(crate) struct Device<'a, D> {
    pub host: &'a D,
    pub lan: Option<&'a Attached>,
}
impl<D: WholePacketDevice> WholePacketDevice for Device<'_, D> {
    fn recv<'a>(&'a self, packet: &'a mut [u8]) -> PacketIoFuture<'a> {
        Box::pin(async move {
            let Some(lan) = self.lan else { return self.host.recv(packet).await; };
            let mut discovery = vec![0_u8; nestlink_sdk::network::packet_access::PACKET_MTU];
            tokio::select! {
                result = self.host.recv(packet) => result,
                result = lan.bridge.recv(&mut discovery) => {
                    let length = result?;
                    if length > packet.len() { return Err(io::ErrorKind::InvalidInput.into()); }
                    packet[..length].copy_from_slice(&discovery[..length]);
                    Ok(length)
                }
            }
        })
    }
    fn send<'a>(&'a self, packet: &'a [u8]) -> PacketIoFuture<'a> {
        Box::pin(async move {
            if let Some(lan) = self.lan
                && lan.bridge.handles_admitted(packet) {
                return lan.bridge.receive_admitted(packet);
            }
            self.host.send(packet).await
        })
    }
}
