//! Reuse the existing Ed25519 service issuer and bounded transcript encoding.
//! A grouped lease has its own purpose; an older single-edge verifier cannot
//! treat it as permission for the original selected edge.
use super::*;
use nestlink_protocol::service_plane::group::ServiceEdgeGroupView;

pub(super) const GROUP_LEASE: &[u8] = b"NestLink/service-publication-group-lease/v1\0";
const GROUP_AGGREGATE: &[u8] = b"NestLink/service-publication-group-allocation/v1\0";

pub fn service_edge_group_digest(group: &ServiceEdgeGroupView) -> Result<[u8;32],ContractError> {
    Ok(digest(&domain_message(GROUP_AGGREGATE, &encode(group,SERVICE_MESSAGE_BYTES)?)))
}
pub(super) fn check_binding(claims: &ServiceLeaseClaims) -> Result<(),ContractError> {
    if let Some(binding) = &claims.edge_group {
        binding.validate(claims)?;
        if service_edge_group_digest(&binding.group)? != binding.aggregate_sha256 { return Err(invalid()); }
    }
    Ok(())
}
pub(super) fn purpose(claims: &ServiceLeaseClaims) -> &'static [u8] {
    if claims.edge_group.is_some() { GROUP_LEASE } else { LEASE }
}
