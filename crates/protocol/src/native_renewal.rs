//! Closed native renewal envelope, carried only by the post-proof private port.
use crate::{CONTROL_BYTES, ContractError, ErrorCode};
pub const VERSION: u8 = 1;
pub const MAX_BYTES: usize = if CONTROL_BYTES < 65_536 {
    CONTROL_BYTES as usize
} else {
    65_536
};
pub const HELLO: &[u8] = b"NL-RENEW\0\x01";
const HEADER: usize = 5 + 1 + 16 + 32 + 8 + 8 + 8 + 32 + 32 + 4;
fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid native renewal envelope")
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Offer = 1,
    HostProof = 2,
    Grant = 3,
    Applied = 4,
    Abort = 5,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kind: Kind,
    pub session: [u8; 16],
    pub deployment: [u8; 32],
    pub epoch: u64,
    pub generation: u64,
    pub old_sequence: u64,
    pub round: [u8; 32],
    pub old_permit: [u8; 32],
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
}
impl Envelope {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let valid = match self.kind {
            Kind::Offer | Kind::Abort => self.payload.is_empty(),
            Kind::HostProof => self.payload.len() == 112,
            Kind::Grant => self.payload.len() > 64,
            Kind::Applied => self.payload.len() == 32,
        };
        if !valid
            || self.old_sequence == 0
            || self.old_sequence.checked_add(1).is_none()
            || self.generation == 0
            || self.round == [0; 32]
            || self.payload.len() > MAX_BYTES.saturating_sub(HEADER + 64)
        {
            return Err(invalid());
        }
        let mut b = Vec::with_capacity(HEADER + self.payload.len());
        b.extend_from_slice(b"NLRN\x01");
        b.push(self.kind as u8);
        b.extend_from_slice(&self.session);
        b.extend_from_slice(&self.deployment);
        for v in [self.epoch, self.generation, self.old_sequence] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        b.extend_from_slice(&self.round);
        b.extend_from_slice(&self.old_permit);
        b.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        b.extend_from_slice(&self.payload);
        Ok(b)
    }
    pub fn encode(&self) -> Result<Vec<u8>, ContractError> {
        let mut b = self.signing_bytes()?;
        b.extend_from_slice(&self.signature);
        Ok(b)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() < HEADER + 64 || bytes.len() > MAX_BYTES || &bytes[..5] != b"NLRN\x01" {
            return Err(invalid());
        }
        let kind = match bytes[5] {
            1 => Kind::Offer,
            2 => Kind::HostProof,
            3 => Kind::Grant,
            4 => Kind::Applied,
            5 => Kind::Abort,
            _ => return Err(invalid()),
        };
        let mut offset = 6;
        fn take<const N: usize>(b: &[u8], o: &mut usize) -> Result<[u8; N], ContractError> {
            let end = o.checked_add(N).ok_or_else(invalid)?;
            let result = b
                .get(*o..end)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?;
            *o = end;
            Ok(result)
        }
        let session = take(bytes, &mut offset)?;
        let deployment = take(bytes, &mut offset)?;
        let epoch = u64::from_be_bytes(take(bytes, &mut offset)?);
        let generation = u64::from_be_bytes(take(bytes, &mut offset)?);
        let old_sequence = u64::from_be_bytes(take(bytes, &mut offset)?);
        let round = take(bytes, &mut offset)?;
        let old_permit = take(bytes, &mut offset)?;
        let size = u32::from_be_bytes(take(bytes, &mut offset)?) as usize;
        if offset.checked_add(size).and_then(|n| n.checked_add(64)) != Some(bytes.len()) {
            return Err(invalid());
        }
        let payload = bytes[offset..offset + size].to_vec();
        offset += size;
        let signature = take(bytes, &mut offset)?;
        let value = Self {
            kind,
            session,
            deployment,
            epoch,
            generation,
            old_sequence,
            round,
            old_permit,
            payload,
            signature,
        };
        if value.encode()?.as_slice() != bytes {
            return Err(invalid());
        }
        Ok(value)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    fn offer() -> Envelope {
        Envelope {
            kind: Kind::Offer,
            session: [1; 16],
            deployment: [2; 32],
            epoch: 1,
            generation: 1,
            old_sequence: 1,
            round: [3; 32],
            old_permit: [4; 32],
            payload: Vec::new(),
            signature: [5; 64],
        }
    }
    #[test]
    fn bounded_closed_native_renewal_codec_rejects_unknown_trailing_and_oversize() {
        let original = offer();
        let bytes = original.encode().expect("valid");
        assert_eq!(Envelope::decode(&bytes).expect("decode"), original);
        for kind in [0, 6, 255] {
            let mut bad = bytes.clone();
            bad[5] = kind;
            assert!(Envelope::decode(&bad).is_err());
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(Envelope::decode(&bad).is_err());
        assert!(Envelope::decode(&vec![0; MAX_BYTES + 1]).is_err());
        for n in 0..bytes.len() {
            assert!(Envelope::decode(&bytes[..n]).is_err());
        }
    }
    #[test]
    fn renewal_variant_payloads_and_sequence_are_closed() {
        let mut value = offer();
        value.payload.push(0);
        assert!(value.encode().is_err());
        value.payload.clear();
        value.old_sequence = u64::MAX;
        assert!(value.encode().is_err());
        value.old_sequence = 1;
        value.kind = Kind::HostProof;
        value.payload = vec![0; 111];
        assert!(value.encode().is_err());
        value.payload.push(0);
        assert!(value.encode().is_ok());
        value.kind = Kind::Applied;
        assert!(value.encode().is_err());
    }
}
