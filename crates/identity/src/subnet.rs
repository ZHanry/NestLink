//! Separate mapping purpose over the original network Ed25519 authority.
//! A mapping is publication/translation authority, never NetworkAccess.
use crate::{digest, domain_message, verify_signature, network::{NetworkAuthoritySigner, NetworkVerification, VerifiedNetworkGrant}};
use ed25519_dalek::Signer;
use nestlink_protocol::{ContractError, ErrorCode, network::GrantClaims, network_topology::BootIncarnation, subnet::{SignedSubnetMapping, SubnetMappingClaims}};

const MAPPING_DOMAIN: &[u8] = b"NestLink/subnet/v1/exact-mapping\0";
const REFERENCE_DOMAIN: &[u8] = b"NestLink/subnet/v1/mapping-reference\0";

/// Facts from the current authenticated management snapshot, never from the
/// mapping being verified. The accepted lease must still identify this boot.
pub struct SubnetGatewayState<'a> {
    pub node_id: &'a str,
    pub public_key: &'a [u8; 32],
    pub incarnation: &'a BootIncarnation,
    pub mapping_revision: u64,
    pub lease_expires_at_ms: u64,
}

#[derive(Clone)]
pub struct VerifiedSubnetMapping {
    claims: SubnetMappingClaims,
    digest: [u8; 32],
    issuer: [u8; 32],
    route_export: VerifiedNetworkGrant,
}
impl NetworkAuthoritySigner {
    pub fn sign_subnet_mapping(&self, claims: &SubnetMappingClaims) -> Result<SignedSubnetMapping, ContractError> {
        let claims = claims.canonical_bytes()?;
        let signature = self.key.sign(&domain_message(MAPPING_DOMAIN, &claims)).to_bytes().to_vec();
        Ok(SignedSubnetMapping { claims, signature })
    }
}
impl VerifiedSubnetMapping {
    pub fn claims(&self) -> &SubnetMappingClaims { &self.claims }
    pub fn digest(&self) -> [u8; 32] { self.digest }
    pub fn route_export(&self) -> &VerifiedNetworkGrant { &self.route_export }
    pub fn check_current(&self, context: &NetworkVerification<'_>, gateway: &SubnetGatewayState<'_>) -> Result<(), ContractError> {
        let claims = &self.claims;
        let scope = &claims.scope;
        if self.issuer != *context.authority_key || scope.deployment_id != context.deployment_id || scope.space_id != context.space_id {
            return Err(denied("subnet mapping authority or space differs"));
        }
        if scope.policy_epoch != context.policy_epoch || context.revoked_grant_ids.contains(&scope.grant_id)
            || claims.mapping_revision != gateway.mapping_revision
        { return Err(ContractError::new(ErrorCode::PolicyRevoked, "subnet mapping revision or policy was revoked")); }
        if !scope.valid_at(context.now_ms) || context.now_ms >= gateway.lease_expires_at_ms {
            return Err(ContractError::new(ErrorCode::LeaseExpired, "subnet mapping or original gateway lease expired"));
        }
        if claims.gateway_node_id != gateway.node_id || claims.gateway_public_key != *gateway.public_key
            || claims.gateway_incarnation != *gateway.incarnation
        { return Err(denied("subnet mapping belongs to another gateway key or boot")); }
        self.route_export.check_current(context)?;
        let GrantClaims::RouteExport(export) = self.route_export.claims() else { return Err(denied("subnet mapping requires a separate RouteExport")); };
        if self.route_export.digest() != claims.route_export_digest || export.gateway != claims.gateway
            || !export.prefixes.contains(&claims.original) || !export.prefixes.contains(&claims.alias)
            || scope.not_before_ms < export.scope.not_before_ms || scope.expires_at_ms > export.scope.expires_at_ms
            || scope.grant_id == export.scope.grant_id
        { return Err(denied("subnet mapping expands or replaces its exact RouteExport")); }
        Ok(())
    }
    /// A concrete local owner must also intersect this with the original
    /// NetworkAccess/path deadline; a refreshed node lease never renews either.
    pub fn effective_expires_at_ms(&self, gateway: &SubnetGatewayState<'_>) -> u64 {
        self.claims.scope.expires_at_ms.min(gateway.lease_expires_at_ms)
    }
}

pub fn verify_subnet_mapping(signed: &SignedSubnetMapping, context: &NetworkVerification<'_>, route_export: VerifiedNetworkGrant, gateway: &SubnetGatewayState<'_>) -> Result<VerifiedSubnetMapping, ContractError> {
    signed.validate()?;
    verify_signature(context.authority_key, MAPPING_DOMAIN, &signed.claims, &signed.signature)?;
    let claims = SubnetMappingClaims::decode_canonical(&signed.claims)?;
    let mut reference = REFERENCE_DOMAIN.to_vec();
    reference.extend_from_slice(context.authority_key);
    reference.extend_from_slice(&signed.claims);
    let mapping = VerifiedSubnetMapping { claims, digest: digest(&reference), issuer: *context.authority_key, route_export };
    mapping.check_current(context, gateway)?;
    Ok(mapping)
}
fn denied(reason: &'static str) -> ContractError { ContractError::new(ErrorCode::PermissionRequired, reason) }

#[cfg(test)]
mod tests;
