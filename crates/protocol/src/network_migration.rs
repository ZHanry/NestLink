//! A closed control transcript for a separately authorized path transition.
//! Parsing these bytes grants neither a path nor permission to move a socket.
use crate::{ContractError, ErrorCode, network::PeerPair};

pub const VERSION: u8 = 1;
pub const MAX_BYTES: usize = 6 + 12 * 32 + 4 * 8 + 2 * 32 + 64;
pub const MAX_CONTROL_LIFETIME_MS: u64 = 2_000;
pub const MAX_DRAIN_MS: u64 = 250;
pub const CONNECTION_BINDING_LABEL: &[u8] = b"NestLink/network/path-migration/connection/v1";

impl Binding {
    /// The leader chooses the short control expiry. Every other field must
    /// already follow the receiver's independently verified original owner.
    pub fn same_scope(&self, other: &Self) -> bool {
        let mut expected = self.clone();
        expected.expires_at_unix_ms = other.expires_at_unix_ms;
        expected == *other
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Proposal = 1,
    Accepted = 2,
    Commit = 3,
    Committed = 4,
}

/// Hash projections of the original verified authorization and both mutually
/// pinned TLS connections. They are compared with the owner's typed inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub deployment: [u8; 32],
    pub space: [u8; 32],
    pub session: [u8; 32],
    pub permit: [u8; 32],
    pub path_grant: [u8; 32],
    pub transport_group: [u8; 32],
    pub peers: PeerPair,
    pub original_route: [u8; 32],
    pub candidate_route: [u8; 32],
    pub original_connection: [u8; 32],
    pub control_connection: [u8; 32],
    pub business_generation: u64,
    pub previous_path_epoch: u64,
    pub next_path_epoch: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub kind: Kind,
    pub binding: Binding,
    pub proposal: [u8; 32],
    pub challenge: [u8; 32],
    pub signature: [u8; 64],
}

fn invalid() -> ContractError {
    ContractError::new(
        ErrorCode::InvalidMessage,
        "invalid path migration control envelope",
    )
}

impl Binding {
    fn digests(&self) -> [[u8; 32]; 12] {
        [
            self.deployment,
            self.space,
            self.session,
            self.permit,
            self.path_grant,
            self.transport_group,
            self.peers.first.0,
            self.peers.second.0,
            self.original_route,
            self.candidate_route,
            self.original_connection,
            self.control_connection,
        ]
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        self.peers.validate()?;
        if self.digests().iter().any(|digest| *digest == [0; 32])
            || self.original_route == self.candidate_route
            || self.business_generation == 0
            || self.previous_path_epoch == 0
            || self.previous_path_epoch.checked_add(1) != Some(self.next_path_epoch)
            || self.expires_at_unix_ms == 0
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl Envelope {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.binding.validate()?;
        if self.proposal == [0; 32] || (self.kind == Kind::Proposal) != (self.challenge == [0; 32])
        {
            return Err(invalid());
        }
        let mut bytes = Vec::with_capacity(MAX_BYTES - 64);
        bytes.extend_from_slice(b"NLMG\x01");
        bytes.push(self.kind as u8);
        for digest in self.binding.digests() {
            bytes.extend_from_slice(&digest);
        }
        for value in [
            self.binding.business_generation,
            self.binding.previous_path_epoch,
            self.binding.next_path_epoch,
            self.binding.expires_at_unix_ms,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&self.proposal);
        bytes.extend_from_slice(&self.challenge);
        Ok(bytes)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ContractError> {
        let mut bytes = self.signing_bytes()?;
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() != MAX_BYTES || &bytes[..5] != b"NLMG\x01" {
            return Err(invalid());
        }
        let kind = match bytes[5] {
            1 => Kind::Proposal,
            2 => Kind::Accepted,
            3 => Kind::Commit,
            4 => Kind::Committed,
            _ => return Err(invalid()),
        };
        let mut offset = 6;
        fn take<const N: usize>(
            bytes: &[u8],
            offset: &mut usize,
        ) -> Result<[u8; N], ContractError> {
            let end = offset.checked_add(N).ok_or_else(invalid)?;
            let value = bytes
                .get(*offset..end)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?;
            *offset = end;
            Ok(value)
        }
        let binding = Binding {
            deployment: take(bytes, &mut offset)?,
            space: take(bytes, &mut offset)?,
            session: take(bytes, &mut offset)?,
            permit: take(bytes, &mut offset)?,
            path_grant: take(bytes, &mut offset)?,
            transport_group: take(bytes, &mut offset)?,
            peers: PeerPair {
                first: crate::network::PeerId(take(bytes, &mut offset)?),
                second: crate::network::PeerId(take(bytes, &mut offset)?),
            },
            original_route: take(bytes, &mut offset)?,
            candidate_route: take(bytes, &mut offset)?,
            original_connection: take(bytes, &mut offset)?,
            control_connection: take(bytes, &mut offset)?,
            business_generation: u64::from_be_bytes(take(bytes, &mut offset)?),
            previous_path_epoch: u64::from_be_bytes(take(bytes, &mut offset)?),
            next_path_epoch: u64::from_be_bytes(take(bytes, &mut offset)?),
            expires_at_unix_ms: u64::from_be_bytes(take(bytes, &mut offset)?),
        };
        let value = Self {
            kind,
            binding,
            proposal: take(bytes, &mut offset)?,
            challenge: take(bytes, &mut offset)?,
            signature: take(bytes, &mut offset)?,
        };
        value.signing_bytes()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
    fn proposal() -> Envelope {
        Envelope {
            kind: Kind::Proposal,
            binding: Binding {
                deployment: [1; 32],
                space: [2; 32],
                session: [3; 32],
                permit: [4; 32],
                path_grant: [5; 32],
                transport_group: [6; 32],
                peers: PeerPair {
                    first: crate::network::PeerId([7; 32]),
                    second: crate::network::PeerId([8; 32]),
                },
                original_route: [9; 32],
                candidate_route: [10; 32],
                original_connection: [11; 32],
                control_connection: [12; 32],
                business_generation: 3,
                previous_path_epoch: 7,
                next_path_epoch: 8,
                expires_at_unix_ms: 30_000,
            },
            proposal: [13; 32],
            challenge: [0; 32],
            signature: [0; 64],
        }
    }
    #[test]
    fn closed_codec_rejects_lengths_unknown_phases_and_invalid_epochs() -> TestResult {
        let original = proposal();
        let bytes = original.encode()?;
        assert_eq!(bytes.len(), MAX_BYTES);
        assert_eq!(Envelope::decode(&bytes)?, original);
        for length in 0..bytes.len() {
            assert!(Envelope::decode(&bytes[..length]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Envelope::decode(&trailing).is_err());
        for kind in [0, 5, 255] {
            let mut altered = bytes.clone();
            altered[5] = kind;
            assert!(Envelope::decode(&altered).is_err());
        }
        for mode in 0..5 {
            let mut altered = original.clone();
            match mode {
                0 => altered.binding.next_path_epoch += 1,
                1 => altered.binding.previous_path_epoch = u64::MAX,
                2 => altered.binding.candidate_route = altered.binding.original_route,
                3 => altered.challenge = [1; 32],
                _ => altered.kind = Kind::Commit,
            }
            assert!(altered.encode().is_err());
        }
        Ok(())
    }
}
