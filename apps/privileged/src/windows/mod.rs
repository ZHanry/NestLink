//! FFI is isolated here; the protocol/gate modules remain safe Rust.
mod client;
mod consent;
mod installation;
pub mod local_port_gate;
mod security;
mod server;
pub use client::{BrokerClient, BrokerInput};
pub use server::{BrokerArgs, run};

/// Business daemons stay at medium integrity, including optional broker installs.
pub fn require_normal_user_process() -> std::io::Result<()> {
    if security::Peer::open(std::process::id())?.is_normal() {
        Ok(())
    } else {
        Err(security::denied())
    }
}

/// Read-only local process identity. These observations are not a broker
/// grant and retain the existing token, incarnation, image and alive checks.
pub struct LocalProcessFacts {
    pub pid: u32,
    pub creation: u64,
    pub image: std::path::PathBuf,
}

pub fn local_process_facts(pid: u32) -> std::io::Result<LocalProcessFacts> {
    let peer = security::Peer::open(pid)?;
    Ok(LocalProcessFacts {
        pid: peer.pid,
        creation: peer.creation,
        image: peer.image,
    })
}

/// Administrative helpers use the same elevated high-integrity gate as the
/// existing local broker. This function never elevates or launches a process.
pub fn require_administrator_process() -> std::io::Result<()> {
    if security::Peer::open(std::process::id())?.is_broker() {
        Ok(())
    } else {
        Err(security::denied())
    }
}

#[cfg(test)]
mod process_identity_tests {
    #[test]
    fn current_business_process_has_a_medium_non_elevated_identity() {
        let peer = match super::security::Peer::open(std::process::id()) {
            Ok(peer) => peer,
            Err(_) => panic!("current process token and image must be queryable"),
        };
        assert!(
            peer.is_normal(),
            "business process must be non-elevated at medium integrity (session {}, elevated {}, integrity {:#x})",
            peer.session,
            peer.elevated,
            peer.integrity,
        );
    }
}
