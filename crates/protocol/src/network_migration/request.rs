//! A reliable standby UNI-stream wake-up, not a signature or switch permit.
//! The receiver compares every byte with its retained original owner before
//! capability negotiation and the independent bilateral signed transcript.
use crate::{ContractError, ErrorCode};
pub const MAX_BYTES: usize = 8 + 5 * 32 + 8;
const MAGIC: &[u8; 8] = b"NLMR0001";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub permit: [u8; 32],
    pub transport_group: [u8; 32],
    pub original_connection: [u8; 32],
    pub original_route: [u8; 32],
    pub candidate_route: [u8; 32],
    pub previous_path_epoch: u64,
}
fn invalid() -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, "invalid path-migration wake-up request")
}
impl Request {
    pub fn encode(&self) -> Result<[u8; MAX_BYTES], ContractError> {
        let fields = [self.permit, self.transport_group, self.original_connection, self.original_route, self.candidate_route];
        if fields.contains(&[0; 32]) || self.original_route == self.candidate_route || self.previous_path_epoch == 0 {
            return Err(invalid());
        }
        let mut bytes = [0; MAX_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        for (index, field) in fields.iter().enumerate() {
            bytes[8 + index * 32..8 + (index + 1) * 32].copy_from_slice(field);
        }
        bytes[MAX_BYTES - 8..].copy_from_slice(&self.previous_path_epoch.to_be_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() != MAX_BYTES || &bytes[..8] != MAGIC { return Err(invalid()); }
        let field = |index| bytes[8 + index * 32..8 + (index + 1) * 32].try_into().map_err(|_| invalid());
        let value = Self { permit: field(0)?, transport_group: field(1)?, original_connection: field(2)?,
            original_route: field(3)?, candidate_route: field(4)?,
            previous_path_epoch: u64::from_be_bytes(bytes[MAX_BYTES - 8..].try_into().map_err(|_| invalid())?) };
        value.encode()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requests_have_one_exact_version_length_original_scope_and_epoch() -> Result<(), ContractError> {
        let value = Request { permit: [1; 32], transport_group: [2; 32], original_connection: [3; 32],
            original_route: [4; 32], candidate_route: [5; 32], previous_path_epoch: 1 };
        let bytes = value.encode()?;
        assert_eq!(Request::decode(&bytes)?, value);
        for length in 0..MAX_BYTES { assert!(Request::decode(&bytes[..length]).is_err()); }
        let mut extra = bytes.to_vec(); extra.push(0);
        assert!(Request::decode(&extra).is_err());
        for index in 0..8 { let mut changed = bytes; changed[index] ^= 1; assert!(Request::decode(&changed).is_err()); }
        let mut zero = value.clone(); zero.previous_path_epoch = 0;
        assert!(zero.encode().is_err());
        zero = value.clone(); zero.original_route = zero.candidate_route;
        assert!(zero.encode().is_err());
        for index in 0..5 {
            let mut zero = bytes; zero[8 + index * 32..8 + (index + 1) * 32].fill(0);
            assert!(Request::decode(&zero).is_err());
        }
        Ok(())
    }
}
