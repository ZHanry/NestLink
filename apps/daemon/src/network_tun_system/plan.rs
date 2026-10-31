use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::network::{NetworkVerification, verify_network_grant};
use nestlink_protocol::network::{GrantClaims, IpPrefix, NetworkAccessClaims, PeerId};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::fs::File;
use std::{collections::BTreeSet, net::IpAddr, path::Path};

#[cfg(target_os = "linux")]
pub(super) const MAX_JSON: u64 = 65_536;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum HostPrincipal {
    Linux {
        uid: u32,
    },
    Windows {
        sid: String,
        session: u32,
        image_volume: u32,
        image_index: u64,
    },
}
impl HostPrincipal {
    pub fn current() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self::Linux {
                uid: rustix::process::geteuid().as_raw(),
            })
        }
        #[cfg(windows)]
        {
            nestlink_privileged::windows::require_normal_user_process()?;
            let process = nestlink_privileged::windows::local_port_gate::ProcessIdentity::read(
                std::process::id(),
            )?;
            Ok(Self::Windows {
                sid: process.sid,
                session: process.session,
                image_volume: process.image_volume,
                image_index: process.image_index,
            })
        }
    }
    fn valid_here(&self) -> bool {
        match self {
            Self::Linux { uid } => cfg!(target_os = "linux") && *uid > 0 && *uid <= i32::MAX as u32,
            Self::Windows {
                sid,
                session,
                image_volume: _,
                image_index,
            } => {
                cfg!(windows)
                    && *session > 0
                    && *image_index > 0
                    && sid.starts_with("S-1-")
                    && sid.len() <= 184
                    && sid
                        .bytes()
                        .all(|b| b == b'S' || b == b'-' || b.is_ascii_digit())
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TunPlan {
    pub schema_version: u16,
    pub owner_id: String,
    pub space_id: String,
    pub process: crate::space_dns_system::ProcessIdentity,
    pub principal: HostPrincipal,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub deployment_id: String,
    pub authority_key: [u8; 32],
    pub local_peer: PeerId,
    pub remote_peer: PeerId,
    pub local_hosts: [IpAddr; 2],
    pub remote_hosts: [IpAddr; 2],
    pub approved_digest: [u8; 32],
    pub policy_epoch: u64,
    pub signed_claims: String,
    pub signature: String,
}
impl TunPlan {
    #[cfg(windows)]
    pub async fn windows_binding(
        &self,
    ) -> Result<nestlink_privileged::windows::network_tun::PacketBinding> {
        use nestlink_privileged::windows::{
            local_port_gate::ProcessIdentity, network_tun::PacketBinding,
        };
        let process = ProcessIdentity::read(self.process.pid())?;
        let HostPrincipal::Windows {
            sid,
            session,
            image_volume,
            image_index,
        } = &self.principal
        else {
            return Err(
                io::Error::other("Windows TUN requires the original Windows principal").into(),
            );
        };
        if process_identity(process.pid).await? != self.process
            || process.sid != *sid
            || process.session != *session
            || process.image_volume != *image_volume
            || process.image_index != *image_index
        {
            return Err(io::Error::other("original Windows TUN principal changed").into());
        }
        let binding = PacketBinding {
            schema_version: 1,
            owner_id: self.owner_id.clone(),
            plan_sha256: self.digest()?,
            process,
            expires_at_ms: self.expires_at_ms,
        };
        binding.check_current_owner()?;
        Ok(binding)
    }
    #[cfg(target_os = "linux")]
    pub fn linux_uid(&self) -> Result<u32> {
        match &self.principal {
            HostPrincipal::Linux { uid } => Ok(*uid),
            _ => Err(
                io::Error::other("Linux TUN requires its explicit original ordinary UID").into(),
            ),
        }
    }
    #[cfg(windows)]
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(nestlink_identity::digest(&serde_json::to_vec(self)?))
    }
    #[cfg(target_os = "linux")]
    pub fn link(&self) -> String {
        format!("nlt{}", &self.owner_id.replace('-', "")[..12])
    }
    pub fn marker(&self) -> String {
        format!("NestLink:tun:v1:{}", self.owner_id)
    }
    pub fn validate(&self, fresh: bool) -> Result {
        let now = system_wall_ms()?;
        if self.schema_version != 2
            || !nestlink_protocol::valid_id(&self.owner_id)
            || !nestlink_protocol::valid_id(&self.space_id)
            || !nestlink_protocol::valid_id(&self.deployment_id)
            || !self.process.valid()
            || !self.principal.valid_here()
            || self.created_at_ms >= self.expires_at_ms
            || self.expires_at_ms - self.created_at_ms > 60_000
            || self.approved_digest == [0; 32]
            || self.authority_key == [0; 32]
            || self.local_peer == self.remote_peer
            || self
                .local_hosts
                .iter()
                .chain(&self.remote_hosts)
                .any(|ip| ip.is_unspecified() || ip.is_loopback() || ip.is_multicast())
            || !self.local_hosts[0].is_ipv4()
            || !self.remote_hosts[0].is_ipv4()
            || !self.local_hosts[1].is_ipv6()
            || !self.remote_hosts[1].is_ipv6()
            || self
                .local_hosts
                .iter()
                .any(|ip| self.remote_hosts.contains(ip))
            || (fresh
                && (self.created_at_ms > now.saturating_add(1000) || now >= self.expires_at_ms))
        {
            return Err(io::Error::other("invalid or expired exact host-only TUN plan").into());
        }
        // Recovery must still authenticate the original bounded signed bytes
        // after expiry; use a time inside their original interval solely for
        // identifying resources. Packet admission always uses current time.
        if self.signed_claims.len() > 24_000 || self.signature.len() != 86 {
            return Err(io::Error::other("TUN signed policy exceeds its bound").into());
        }
        let signed = nestlink_identity::network::SignedNetworkGrant {
            claims: URL_SAFE_NO_PAD.decode(&self.signed_claims)?,
            signature: URL_SAFE_NO_PAD.decode(&self.signature)?,
        };
        let revoked = BTreeSet::new();
        let context = NetworkVerification {
            authority_key: &self.authority_key,
            deployment_id: &self.deployment_id,
            space_id: &self.space_id,
            policy_epoch: self.policy_epoch,
            now_ms: if fresh { now } else { self.created_at_ms },
            revoked_grant_ids: &revoked,
        };
        let grant = verify_network_grant(&signed, &context)?;
        let GrantClaims::NetworkAccess(claims) = grant.claims() else {
            return Err(io::Error::other("TUN plan needs a signed NetworkAccess policy").into());
        };
        if grant.digest() != self.approved_digest || self.expires_at_ms > claims.scope.expires_at_ms
        {
            return Err(io::Error::other(
                "TUN plan does not match the explicitly approved business digest/deadline",
            )
            .into());
        }
        self.check_hosts(claims)
    }
    fn check_hosts(&self, claims: &NetworkAccessClaims) -> Result {
        let (local, remote) = if self.local_peer == claims.source
            && self.remote_peer == claims.destination
        {
            (&claims.source_prefixes, &claims.destination_prefixes)
        } else if self.local_peer == claims.destination && self.remote_peer == claims.source {
            (&claims.destination_prefixes, &claims.source_prefixes)
        } else {
            return Err(io::Error::other("TUN peer pair differs from its signed policy").into());
        };
        for (hosts, prefixes) in [(&self.local_hosts, local), (&self.remote_hosts, remote)] {
            if prefixes.is_empty()
                || prefixes.len() > 2
                || prefixes.iter().any(|prefix| {
                    let host = IpPrefix {
                        network: prefix.network,
                        prefix_len: if prefix.network.is_ipv4() { 32 } else { 128 },
                    };
                    *prefix != host || !hosts.contains(&prefix.network)
                })
            {
                return Err(io::Error::other(
                    "host-only TUN accepts only exact signed /32 or /128 assignments",
                )
                .into());
            }
            // Both OS families are installed only when independently present in
            // this signed access policy; no broad implicit prefix is created.
            if hosts
                .iter()
                .any(|host| !prefixes.iter().any(|prefix| prefix.network == *host))
            {
                return Err(io::Error::other("both exact local and remote IP families require explicit signed host admission").into());
            }
        }
        Ok(())
    }
    pub fn read(path: &Path) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::read_linux(path)
        }
        #[cfg(windows)]
        {
            let input = nestlink_privileged::windows::network_tun::SelectedPlanFile::open(path)?;
            let plan: Self = serde_json::from_slice(&input.bytes()?)?;
            plan.validate(false)?;
            let HostPrincipal::Windows { ref sid, .. } = plan.principal else {
                return Err(io::Error::other(
                    "Windows TUN requires its explicit original SID principal",
                )
                .into());
            };
            input.require_owner(sid)?;
            Ok(plan)
        }
    }
    #[cfg(target_os = "linux")]
    fn read_linux(path: &Path) -> Result<Self> {
        let (bytes, uid) = crate::network_packet_runtime::read_public_plan(path, MAX_JSON)?;
        let plan: Self = serde_json::from_slice(&bytes)?;
        plan.validate(false)?;
        if uid != plan.linux_uid()? {
            return Err(io::Error::other(
                "TUN public input must belong to its captured ordinary UID",
            )
            .into());
        }
        Ok(plan)
    }
    pub fn save_new(&self, path: &Path) -> Result {
        self.validate(true)?;
        if !path.is_absolute() {
            return Err(io::Error::other("absolute new TUN plan output required").into());
        }
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("TUN plan parent missing"))?;
        nestlink_platform_security::check_private_directory(parent)?;
        #[cfg(target_os = "linux")]
        {
            nestlink_platform_security::create_private(path, &serde_json::to_vec_pretty(self)?)?;
            File::open(parent)?.sync_all()?;
        }
        #[cfg(windows)]
        {
            nestlink_privileged::windows::network_tun::save_owner_plan(
                path,
                &serde_json::to_vec_pretty(self)?,
            )?;
        }
        Ok(())
    }
}
