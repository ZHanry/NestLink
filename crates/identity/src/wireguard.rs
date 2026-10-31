//! An independent purpose on the original space Ed25519 authority. WireGuard
//! itself performs X25519 and encrypted packet authentication in the kernel.
use crate::{
    digest, domain_message,
    network::{NetworkAuthoritySigner, NetworkVerification, VerifiedNetworkGrant},
    verify_signature,
};
use ed25519_dalek::Signer;
use nestlink_protocol::{
    ContractError, ErrorCode,
    network::{GrantClaims, IpPrefix, PeerId},
    network_topology::BootIncarnation,
    wireguard::{SignedWireGuardClientBinding, WireGuardClientBindingClaims},
};
use std::net::IpAddr;

const DOMAIN: &[u8] = b"NestLink/wireguard/v1/original-packet-client-binding\0";
const REFERENCE: &[u8] = b"NestLink/wireguard/v1/client-binding-reference\0";
pub struct WireGuardPortalState<'a> {
    pub node_id: &'a str,
    pub public_key: &'a [u8; 32],
    pub incarnation: &'a BootIncarnation,
    pub lease_expires_at_ms: u64,
    pub client_revision: u64,
}
#[derive(Clone)]
pub struct VerifiedWireGuardClientBinding {
    claims: WireGuardClientBindingClaims,
    issuer: [u8; 32],
    digest: [u8; 32],
    access: VerifiedNetworkGrant,
}
impl NetworkAuthoritySigner {
    pub fn sign_wireguard_client_binding(
        &self,
        claims: &WireGuardClientBindingClaims,
    ) -> Result<SignedWireGuardClientBinding, ContractError> {
        let claims = claims.canonical_bytes()?;
        Ok(SignedWireGuardClientBinding {
            signature: self
                .key
                .sign(&domain_message(DOMAIN, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
impl VerifiedWireGuardClientBinding {
    pub fn claims(&self) -> &WireGuardClientBindingClaims {
        &self.claims
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn access(&self) -> &VerifiedNetworkGrant {
        &self.access
    }
    pub fn check_current(
        &self,
        context: &NetworkVerification<'_>,
        portal: &WireGuardPortalState<'_>,
    ) -> Result<(), ContractError> {
        let claims = &self.claims;
        let scope = &claims.scope;
        self.access.check_current(context)?;
        if self.issuer != *context.authority_key
            || scope.deployment_id != context.deployment_id
            || scope.space_id != context.space_id
            || scope.policy_epoch != context.policy_epoch
            || context.revoked_grant_ids.contains(&scope.grant_id)
            || claims.client_revision != portal.client_revision
            || claims.portal_node_id != portal.node_id
            || claims.portal_public_key != *portal.public_key
            || claims.portal_incarnation != *portal.incarnation
        {
            return Err(denied(
                "WireGuard client authority, revision or original portal boot changed",
            ));
        }
        if !scope.valid_at(context.now_ms) || context.now_ms >= portal.lease_expires_at_ms {
            return Err(ContractError::new(
                ErrorCode::LeaseExpired,
                "WireGuard client binding or original portal node lease expired",
            ));
        }
        let GrantClaims::NetworkAccess(access) = self.access.claims() else {
            return Err(denied("WireGuard binding requires original NetworkAccess"));
        };
        if claims.access_digest != self.access.digest()
            || claims.access_grant_id != access.scope.grant_id
            || access.source != PeerId::from_public_key(&claims.portal_public_key)
            || access.source_prefixes.as_slice()
                != [IpPrefix {
                    network: IpAddr::V4(claims.client_address),
                    prefix_len: 32,
                }]
            || claims.committed_bytes != access.byte_limit
            || scope.not_before_ms < access.scope.not_before_ms
            || scope.expires_at_ms > access.scope.expires_at_ms
            || scope.grant_id == access.scope.grant_id
        {
            return Err(denied(
                "WireGuard client expands or replaces original packet business authority",
            ));
        }
        Ok(())
    }
    pub fn effective_expires_at_ms(&self, portal: &WireGuardPortalState<'_>) -> u64 {
        self.claims
            .scope
            .expires_at_ms
            .min(portal.lease_expires_at_ms)
    }
}
pub fn verify_wireguard_client_binding(
    signed: &SignedWireGuardClientBinding,
    context: &NetworkVerification<'_>,
    access: VerifiedNetworkGrant,
    portal: &WireGuardPortalState<'_>,
) -> Result<VerifiedWireGuardClientBinding, ContractError> {
    signed.validate()?;
    verify_signature(
        context.authority_key,
        DOMAIN,
        &signed.claims,
        &signed.signature,
    )?;
    let claims = WireGuardClientBindingClaims::decode_canonical(&signed.claims)?;
    let mut bytes = REFERENCE.to_vec();
    bytes.extend_from_slice(context.authority_key);
    bytes.extend_from_slice(&signed.claims);
    let value = VerifiedWireGuardClientBinding {
        claims,
        issuer: *context.authority_key,
        digest: digest(&bytes),
        access,
    };
    value.check_current(context, portal)?;
    Ok(value)
}
fn denied(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::PermissionRequired, reason)
}
#[cfg(test)]
mod tests;
