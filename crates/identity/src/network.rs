//! Network authority verification, separate from installation and v15 business keys.
use crate::digest;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nestlink_protocol::{
    ContractError, ErrorCode,
    network::{GrantClaims, GrantScope, MembershipClaims, PathClaims, PeerId, PeerPair, Purpose},
};
use std::collections::BTreeSet;
use zeroize::Zeroizing;
mod remote;
pub use remote::{RemoteRouteBinding, remote_route_binding, verify_node_network_resource};

fn node_admission_transcript(
    allocation_id: &str,
    binding: &[u8; 32],
    device_id: &str,
    public_key: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<Vec<u8>, ContractError> {
    if !nestlink_protocol::valid_id(allocation_id)
        || !nestlink_protocol::valid_id(device_id)
        || *binding == [0; 32]
        || *nonce == [0; 32]
    {
        return Err(ContractError::new(ErrorCode::InvalidMessage, "invalid network node admission"));
    }
    let mut transcript = b"NestLink/network-datagram/v1/node-admission\0".to_vec();
    transcript.extend_from_slice(&1u32.to_be_bytes());
    for value in [allocation_id, device_id] {
        transcript.extend_from_slice(&(value.len() as u32).to_be_bytes());
        transcript.extend_from_slice(value.as_bytes());
    }
    transcript.extend_from_slice(binding);
    transcript.extend_from_slice(public_key);
    transcript.extend_from_slice(nonce);
    Ok(transcript)
}

impl crate::InstallationIdentity {
    /// Signs only the bounded, independently domain-separated fresh socket proof.
    pub fn sign_network_node_admission(
        &self,
        allocation_id: &str,
        binding: &[u8; 32],
        device_id: &str,
        nonce: &[u8; 32],
    ) -> Result<[u8; 64], ContractError> {
        Ok(self.key.sign(&node_admission_transcript(
            allocation_id, binding, device_id, &self.public_key(), nonce,
        )?).to_bytes())
    }
}

pub fn verify_network_node_admission(
    allocation_id: &str,
    binding: &[u8; 32],
    device_id: &str,
    public_key: &[u8; 32],
    nonce: &[u8; 32],
    signature: &[u8],
) -> Result<(), ContractError> {
    let invalid = || ContractError::new(ErrorCode::IdentityMismatch, "invalid network node possession proof");
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| invalid())?;
    let signature = Signature::from_slice(signature).map_err(|_| invalid())?;
    key.verify_strict(&node_admission_transcript(allocation_id, binding, device_id, public_key, nonce)?, &signature)
        .map_err(|_| invalid())
}

pub struct NetworkAuthoritySigner {
    key: SigningKey,
}

/// Bytes remain bounded and canonical; callers must not log signed credentials.
#[derive(Clone)]
pub struct SignedNetworkGrant {
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone)]
pub struct VerifiedNetworkGrant {
    claims: GrantClaims,
    digest: [u8; 32],
    issuer: [u8; 32],
}

/// One signed membership bound to the expected installation, device key and
/// membership epoch. Construction requires those expectations from trusted
/// installation state; a member's role does not authorize a business operation.
#[derive(Clone)]
pub struct VerifiedMembership {
    grant: VerifiedNetworkGrant,
    claims: MembershipClaims,
}

/// The complete network authorization chain for one peer pair and purpose.
///
/// This authorizes only a network path. SessionPermit, ServiceLease and
/// NetworkAccessGrant validation remains the business admission caller's job.
/// No public field permits constructing or changing an unchecked chain.
#[derive(Clone)]
pub struct VerifiedNetworkPath {
    memberships: [VerifiedMembership; 2],
    connectivity: VerifiedNetworkGrant,
    path: VerifiedNetworkGrant,
    claims: PathClaims,
    transport_group_id: [u8; 32],
}

/// Values must come from the current trusted control-plane policy snapshot.
/// A caller-provided stale snapshot is not a revocation service.
pub struct NetworkVerification<'a> {
    pub authority_key: &'a [u8; 32],
    pub deployment_id: &'a str,
    pub space_id: &'a str,
    pub policy_epoch: u64,
    pub now_ms: u64,
    pub revoked_grant_ids: &'a BTreeSet<String>,
}

impl NetworkAuthoritySigner {
    pub fn from_master_seed(seed: &[u8; 32]) -> Result<Self, ContractError> {
        let mut derived = Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(Some(b"NestLink/network/v1/authority-keys"), seed)
            .expand(b"network-authority-ed25519", &mut *derived)
            .map_err(|_| {
                ContractError::new(
                    ErrorCode::InternalError,
                    "network authority derivation failed",
                )
            })?;
        Ok(Self {
            key: SigningKey::from_bytes(&derived),
        })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn sign(&self, claims: &GrantClaims) -> Result<SignedNetworkGrant, ContractError> {
        let message = claims.signing_message()?;
        Ok(SignedNetworkGrant {
            claims: claims.canonical_bytes()?,
            signature: self.key.sign(&message).to_bytes().to_vec(),
        })
    }
}

impl VerifiedNetworkGrant {
    pub fn claims(&self) -> &GrantClaims {
        &self.claims
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn issuer(&self) -> [u8; 32] {
        self.issuer
    }

    /// Recheck live expiry and the current policy/revocation snapshot before use.
    pub fn check_current(&self, context: &NetworkVerification<'_>) -> Result<(), ContractError> {
        let scope = self.claims.scope();
        if self.issuer != *context.authority_key
            || scope.deployment_id != context.deployment_id
            || scope.space_id != context.space_id
        {
            return Err(ContractError::new(
                ErrorCode::IdentityMismatch,
                "network grant authority or space mismatch",
            ));
        }
        if scope.policy_epoch != context.policy_epoch
            || context.revoked_grant_ids.contains(&scope.grant_id)
        {
            return Err(ContractError::new(
                ErrorCode::PolicyRevoked,
                "network grant policy was replaced or revoked",
            ));
        }
        if !scope.valid_at(context.now_ms) {
            return Err(ContractError::new(
                ErrorCode::LeaseExpired,
                "network grant is outside its lifetime",
            ));
        }
        Ok(())
    }

    /// Membership establishes one device binding, never business access.
    pub fn expect_member(
        &self,
        context: &NetworkVerification<'_>,
        installation_id: &str,
        public_key: &[u8; 32],
        membership_epoch: u64,
    ) -> Result<PeerId, ContractError> {
        self.check_current(context)?;
        let GrantClaims::Membership(member) = &self.claims else {
            return Err(ContractError::new(
                ErrorCode::PermissionRequired,
                "a membership grant is required",
            ));
        };
        if member.installation_id != installation_id
            || member.public_key != *public_key
            || member.membership_epoch != membership_epoch
        {
            return Err(ContractError::new(
                ErrorCode::IdentityMismatch,
                "membership device binding mismatch",
            ));
        }
        Ok(member.peer)
    }
}

impl VerifiedMembership {
    pub fn from_grant(
        grant: VerifiedNetworkGrant,
        context: &NetworkVerification<'_>,
        installation_id: &str,
        public_key: &[u8; 32],
        membership_epoch: u64,
    ) -> Result<Self, ContractError> {
        grant.expect_member(context, installation_id, public_key, membership_epoch)?;
        let GrantClaims::Membership(claims) = &grant.claims else {
            return Err(ContractError::new(
                ErrorCode::PermissionRequired,
                "a membership grant is required",
            ));
        };
        let claims = claims.clone();
        Ok(Self { grant, claims })
    }

    pub fn claims(&self) -> &MembershipClaims {
        &self.claims
    }
    pub fn peer(&self) -> PeerId {
        self.claims.peer
    }
    pub fn digest(&self) -> [u8; 32] {
        self.grant.digest()
    }

    pub fn check_current(&self, context: &NetworkVerification<'_>) -> Result<(), ContractError> {
        self.grant.check_current(context)
    }
}

impl VerifiedNetworkPath {
    /// Construct a path only after both device-bound memberships are verified.
    ///
    /// Before supplying `expected_business_grant_digest`, the caller must
    /// independently verify the business credential's signature, purpose,
    /// endpoints, scope, lifetime, policy and current revocation state. This
    /// method checks its exact digest reference; it does not validate that
    /// credential or authorize remote input, services or raw IP injection.
    pub fn from_grants(
        context: &NetworkVerification<'_>,
        mut memberships: [VerifiedMembership; 2],
        connectivity: VerifiedNetworkGrant,
        path: VerifiedNetworkGrant,
        expected_business_grant_digest: [u8; 32],
    ) -> Result<Self, ContractError> {
        for member in &memberships {
            member.check_current(context)?;
        }
        connectivity.check_current(context)?;
        path.check_current(context)?;
        let GrantClaims::Connectivity(connection) = connectivity.claims() else {
            return Err(ContractError::new(
                ErrorCode::PermissionRequired,
                "a connectivity grant is required",
            ));
        };
        let GrantClaims::Path(path_claims) = path.claims() else {
            return Err(ContractError::new(
                ErrorCode::PermissionRequired,
                "a path grant is required",
            ));
        };
        if memberships[0].peer() > memberships[1].peer() {
            memberships.swap(0, 1);
        }
        let peers = PeerPair::new(memberships[0].peer(), memberships[1].peer())?;
        if connection.peers != peers || path_claims.peers != peers {
            return Err(ContractError::new(
                ErrorCode::IdentityMismatch,
                "network chain peer pair mismatch",
            ));
        }
        if connection.membership_digests != [memberships[0].digest(), memberships[1].digest()]
            || path_claims.connectivity_grant_digest != connectivity.digest()
            || connection.business_grant_digest != expected_business_grant_digest
            || connection.purpose != path_claims.purpose
        {
            return Err(ContractError::new(
                ErrorCode::PermissionRequired,
                "network chain purpose or grant reference mismatch",
            ));
        }
        for member in &memberships {
            require_contained_lifetime(&connection.scope, &member.claims().scope)?;
        }
        require_contained_lifetime(&path_claims.scope, &connection.scope)?;
        // Unlike the protocol's unverified helper, this identity includes the
        // verified issuer and can be obtained only from a complete valid chain.
        let mut group = b"NestLink/network/v1/transport-group\0".to_vec();
        group.extend_from_slice(&path.issuer());
        group.extend_from_slice(&path.claims().signing_message()?);
        let claims = path_claims.clone();
        Ok(Self {
            memberships,
            connectivity,
            path,
            claims,
            transport_group_id: digest(&group),
        })
    }

    pub fn peers(&self) -> PeerPair {
        self.claims.peers
    }
    pub fn purpose(&self) -> Purpose {
        self.claims.purpose
    }
    pub fn claims(&self) -> &PathClaims {
        &self.claims
    }
    pub fn transport_group_id(&self) -> [u8; 32] {
        self.transport_group_id
    }

    /// Recheck every retained chain object against one current trusted snapshot
    /// before opening or continuing traffic. Business admission is separate.
    pub fn check_current(&self, context: &NetworkVerification<'_>) -> Result<(), ContractError> {
        for member in &self.memberships {
            member.check_current(context)?;
        }
        self.connectivity.check_current(context)?;
        self.path.check_current(context)
    }

    /// An allowed route is a network policy result, never business admission.
    pub fn check_route(
        &self,
        context: &NetworkVerification<'_>,
        relays: &[PeerId],
    ) -> Result<(), ContractError> {
        self.check_current(context)?;
        if !self.claims.policy.allows(self.claims.peers, relays) {
            return Err(ContractError::new(
                ErrorCode::PermissionRequired,
                "route is outside the signed path policy",
            ));
        }
        Ok(())
    }
}

fn require_contained_lifetime(
    child: &GrantScope,
    parent: &GrantScope,
) -> Result<(), ContractError> {
    if child.not_before_ms < parent.not_before_ms || child.expires_at_ms > parent.expires_at_ms {
        return Err(ContractError::new(
            ErrorCode::PermissionRequired,
            "child network grant expands its parent's lifetime",
        ));
    }
    Ok(())
}

pub fn verify_network_grant(
    signed: &SignedNetworkGrant,
    context: &NetworkVerification<'_>,
) -> Result<VerifiedNetworkGrant, ContractError> {
    let claims = GrantClaims::decode_canonical(&signed.claims)?;
    // Canonical decoding checked equality with the original bytes. The message
    // below contains those exact bytes, including the grant kind and schema.
    let mut message = claims.domain().to_vec();
    let length = u32::try_from(signed.claims.len()).map_err(|_| {
        ContractError::new(
            ErrorCode::CapacityExceeded,
            "network grant exceeds its byte budget",
        )
    })?;
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(&signed.claims);
    let invalid_signature = || {
        ContractError::new(
            ErrorCode::IdentityMismatch,
            "invalid network signature or authority key",
        )
    };
    let authority =
        VerifyingKey::from_bytes(context.authority_key).map_err(|_| invalid_signature())?;
    let signature = Signature::from_slice(&signed.signature).map_err(|_| invalid_signature())?;
    authority
        .verify_strict(&message, &signature)
        .map_err(|_| invalid_signature())?;
    // The same claims signed by another trusted authority must have a distinct
    // reference. Keep the reference domain separate from the signature domain.
    let mut reference = b"NestLink/network/v1/grant-digest\0".to_vec();
    reference.extend_from_slice(context.authority_key);
    reference.extend_from_slice(&message);
    let verified = VerifiedNetworkGrant {
        claims,
        digest: digest(&reference),
        issuer: *context.authority_key,
    };
    verified.check_current(context)?;
    Ok(verified)
}
