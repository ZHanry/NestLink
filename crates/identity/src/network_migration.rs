//! Installation signatures are separate from every management, renewal and
//! recovery purpose. A verified signature alone is not route authorization.
use crate::{ContractError, InstallationIdentity, Signer, domain_message, verify_signature};
use nestlink_protocol::network_migration::Envelope;
use rand_core::{OsRng, RngCore};

const DOMAIN: &[u8] = b"NestLink/network/path-migration-control/v1\0";
mod transcript;
pub use transcript::{Committed, Phase, Transcript};

impl InstallationIdentity {
    pub fn sign_network_migration(&self, envelope: &Envelope) -> Result<[u8; 64], ContractError> {
        Ok(self
            .key
            .sign(&domain_message(DOMAIN, &envelope.signing_bytes()?))
            .to_bytes())
    }
}

pub fn fresh_challenge() -> [u8; 32] {
    let mut challenge = [0; 32];
    while challenge == [0; 32] {
        OsRng.fill_bytes(&mut challenge);
    }
    challenge
}

pub fn verify(envelope: &Envelope, public_key: &[u8; 32]) -> Result<(), ContractError> {
    verify_signature(
        public_key,
        DOMAIN,
        &envelope.signing_bytes()?,
        &envelope.signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nestlink_protocol::{
        network::{PeerId, PeerPair},
        network_migration::{Binding, Kind},
    };
    #[test]
    fn signature_covers_both_connections_scope_epochs_phase_and_challenges()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let identity = InstallationIdentity::generate();
        let mut envelope = Envelope {
            kind: Kind::Commit,
            binding: Binding {
                deployment: [1; 32],
                space: [2; 32],
                session: [3; 32],
                permit: [4; 32],
                path_grant: [5; 32],
                transport_group: [6; 32],
                peers: PeerPair::new(PeerId([7; 32]), PeerId([8; 32]))?,
                original_route: [9; 32],
                candidate_route: [10; 32],
                original_connection: [11; 32],
                control_connection: [12; 32],
                business_generation: 3,
                previous_path_epoch: 7,
                next_path_epoch: 8,
                expires_at_unix_ms: 30_000,
            },
            proposal: fresh_challenge(),
            challenge: fresh_challenge(),
            signature: [0; 64],
        };
        envelope.signature = identity.sign_network_migration(&envelope)?;
        verify(&envelope, &identity.public_key())?;
        assert!(verify(&envelope, &InstallationIdentity::generate().public_key()).is_err());
        for mode in 0..13 {
            let mut altered = envelope.clone();
            match mode {
                0 => altered.binding.deployment[0] ^= 1,
                1 => altered.binding.space[0] ^= 1,
                2 => altered.binding.session[0] ^= 1,
                3 => altered.binding.permit[0] ^= 1,
                4 => altered.binding.path_grant[0] ^= 1,
                5 => altered.binding.transport_group[0] ^= 1,
                6 => altered.binding.original_route[0] ^= 1,
                7 => altered.binding.candidate_route[0] ^= 1,
                8 => altered.binding.original_connection[0] ^= 1,
                9 => altered.binding.control_connection[0] ^= 1,
                10 => altered.proposal[0] ^= 1,
                11 => altered.challenge[0] ^= 1,
                _ => altered.kind = Kind::Accepted,
            }
            assert!(verify(&altered, &identity.public_key()).is_err());
        }
        Ok(())
    }
}
