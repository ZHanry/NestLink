//! FFI is isolated here; the protocol/gate modules remain safe Rust.
mod client;
mod consent;
mod installation;
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
