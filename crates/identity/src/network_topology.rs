//! Publication authority and node observations have distinct signing purposes.
//! Verified values remain observations; none authorize forwarding or IP access.
use crate::{
    digest,
    network::{NetworkAuthoritySigner, NetworkVerification, VerifiedNetworkGrant},
    nodes::NodeIdentity,
};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
pub use nestlink_protocol::network_topology::{
    SignedTopologyAdvertisement, SignedTopologyPublisher, SignedTopologyReport,
    SignedTopologyUpdate,
};
use nestlink_protocol::{
    ContractError, ErrorCode,
    network::{GrantClaims, GrantScope},
    network_topology::{
        BootIncarnation, MAX_TTL_MS, SCHEMA_VERSION, TopologyAdvertisement,
        TopologyPublisherClaims, TopologyReport, TopologyUpdate,
    },
};

const PUBLISHER: &[u8] = b"NestLink/network-topology/v1/publisher\0";
const REPORT: &[u8] = b"NestLink/network-topology/v1/node-report\0";
const ADVERTISEMENT: &[u8] = b"NestLink/network-topology/v1/authority-advertisement\0";
const UPDATE: &[u8] = b"NestLink/network-topology/v1/authority-update\0";

#[derive(Clone)]
pub struct VerifiedTopologyPublisher {
    claims: TopologyPublisherClaims,
    digest: [u8; 32],
    issuer: [u8; 32],
    route_exports: Vec<VerifiedNetworkGrant>,
}
#[derive(Clone)]
pub struct VerifiedTopologyReport {
    claims: TopologyReport,
    digest: [u8; 32],
    signature: Vec<u8>,
    publisher: VerifiedTopologyPublisher,
}
#[derive(Clone)]
pub struct VerifiedTopologyAdvertisement {
    claims: TopologyAdvertisement,
    digest: [u8; 32],
    issuer: [u8; 32],
    envelope_digest: [u8; 32],
    publisher: VerifiedTopologyPublisher,
}
/// The outer batch signature and request nonce are verified. Each upsert still
/// needs its current publisher/report verification before entering a route graph.
#[derive(Clone)]
pub struct VerifiedTopologyUpdate {
    claims: TopologyUpdate,
    digest: [u8; 32],
    issuer: [u8; 32],
    envelope_digest: [u8; 32],
}

impl NetworkAuthoritySigner {
    /// The management owner selects scope and publication rights from current
    /// trusted policy. This signer cannot turn a node report into such rights.
    pub fn sign_topology_publisher(
        &self,
        claims: &TopologyPublisherClaims,
    ) -> Result<SignedTopologyPublisher, ContractError> {
        let claims = claims.canonical_bytes()?;
        let signature = self
            .key
            .sign(&message(PUBLISHER, &claims)?)
            .to_bytes()
            .to_vec();
        Ok(SignedTopologyPublisher { claims, signature })
    }

    /// Only an already verified node report can construct an advertisement.
    /// Management supplies current admission time and its live lease bound.
    pub fn sign_topology_advertisement(
        &self,
        report: &VerifiedTopologyReport,
        not_before_ms: u64,
        expires_at_ms: u64,
    ) -> Result<SignedTopologyAdvertisement, ContractError> {
        if self.public_key() != report.publisher.issuer
            || not_before_ms < report.claims.not_before_ms
            || not_before_ms < report.publisher.claims.scope.not_before_ms
        {
            return Err(denied(
                "topology advertisement signer or admission time differs",
            ));
        }
        let expires_at_ms = expires_at_ms
            .min(report.claims.expires_at_ms)
            .min(report.publisher.claims.scope.expires_at_ms)
            .min(
                not_before_ms
                    .checked_add(MAX_TTL_MS)
                    .ok_or_else(|| denied("topology time overflow"))?,
            );
        let claims = TopologyAdvertisement {
            schema_version: SCHEMA_VERSION,
            report: report.claims.clone(),
            report_signature: report.signature.clone(),
            report_digest: report.digest,
            not_before_ms,
            expires_at_ms,
        }
        .canonical_bytes()?;
        let signature = self
            .key
            .sign(&message(ADVERTISEMENT, &claims)?)
            .to_bytes()
            .to_vec();
        Ok(SignedTopologyAdvertisement { claims, signature })
    }

    /// The Store builds this bounded batch in its journal transaction. The
    /// signature also authenticates withdrawals whose old report has expired.
    pub fn sign_topology_update(
        &self,
        update: &TopologyUpdate,
    ) -> Result<SignedTopologyUpdate, ContractError> {
        let claims = update.canonical_bytes()?;
        let signature = self
            .key
            .sign(&message(UPDATE, &claims)?)
            .to_bytes()
            .to_vec();
        Ok(SignedTopologyUpdate { claims, signature })
    }
}

impl NodeIdentity {
    pub fn sign_topology_report(
        &self,
        report: &TopologyReport,
    ) -> Result<SignedTopologyReport, ContractError> {
        if report.peer != nestlink_protocol::network::PeerId::from_public_key(&self.public_key()) {
            return Err(denied("topology report node key differs"));
        }
        let claims = report.canonical_bytes()?;
        let signature = self
            .key
            .sign(&message(REPORT, &claims)?)
            .to_bytes()
            .to_vec();
        Ok(SignedTopologyReport { claims, signature })
    }
}

impl VerifiedTopologyPublisher {
    pub fn claims(&self) -> &TopologyPublisherClaims {
        &self.claims
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// `incarnation` must come from management's current accepted node lease,
    /// never the report currently being authenticated.
    pub fn check_current(
        &self,
        context: &NetworkVerification<'_>,
        incarnation: &BootIncarnation,
    ) -> Result<(), ContractError> {
        if self.issuer != *context.authority_key || self.claims.incarnation != *incarnation {
            return Err(mismatch("topology authority or boot incarnation differs"));
        }
        check_scope(&self.claims.scope, context)?;
        for authorization in &self.claims.route_export_digests {
            let grant = self
                .route_exports
                .iter()
                .find(|grant| grant.digest() == *authorization)
                .ok_or_else(|| denied("missing topology RouteExport proof"))?;
            grant.check_current(context)?;
            let GrantClaims::RouteExport(export) = grant.claims() else {
                return Err(denied("topology prefixes require RouteExport"));
            };
            if export.gateway != self.claims.peer
                || self.claims.scope.not_before_ms < export.scope.not_before_ms
                || self.claims.scope.expires_at_ms > export.scope.expires_at_ms
            {
                return Err(denied("topology publication expands RouteExport"));
            }
        }
        for prefix in &self.claims.allowed_prefixes {
            let permitted = self.route_exports.iter().any(|grant| {
                self.claims.route_export_digests.contains(&grant.digest())
                    && matches!(grant.claims(), GrantClaims::RouteExport(export)
                        if export.gateway == self.claims.peer && export.prefixes.contains(prefix))
            });
            if !permitted {
                return Err(denied(
                    "topology prefix has no exact RouteExport permission",
                ));
            }
        }
        Ok(())
    }
}
impl VerifiedTopologyReport {
    pub fn claims(&self) -> &TopologyReport {
        &self.claims
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
impl VerifiedTopologyAdvertisement {
    pub fn claims(&self) -> &TopologyAdvertisement {
        &self.claims
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Binds the exact canonical signed envelope, including its signature.
    pub fn envelope_digest(&self) -> [u8; 32] {
        self.envelope_digest
    }
    /// Non-secret revocation references allow a bounded graph projection to
    /// retain these IDs without caching complete export grant credentials.
    pub fn publication_grant_ids(&self) -> Vec<String> {
        let mut ids = vec![self.publisher.claims.scope.grant_id.clone()];
        for authorization in &self.publisher.claims.route_export_digests {
            if let Some(grant) = self
                .publisher
                .route_exports
                .iter()
                .find(|grant| grant.digest() == *authorization)
            {
                let id = &grant.claims().scope().grant_id;
                if !ids.contains(id) {
                    ids.push(id.clone());
                }
            }
        }
        ids
    }
    pub fn check_current(&self, context: &NetworkVerification<'_>) -> Result<(), ContractError> {
        if self.issuer != *context.authority_key {
            return Err(mismatch("topology advertisement authority differs"));
        }
        self.publisher
            .check_current(context, &self.claims.report.incarnation)?;
        if self.claims.report.deployment_id != context.deployment_id
            || self.claims.report.space_id != context.space_id
            || self.claims.report.policy_epoch != context.policy_epoch
        {
            return Err(mismatch("topology advertisement scope differs"));
        }
        current_time(
            self.claims.not_before_ms,
            self.claims.expires_at_ms,
            context.now_ms,
        )
    }
}
impl VerifiedTopologyUpdate {
    pub fn claims(&self) -> &TopologyUpdate {
        &self.claims
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn envelope_digest(&self) -> [u8; 32] {
        self.envelope_digest
    }
    pub fn check_current(&self, context: &NetworkVerification<'_>) -> Result<(), ContractError> {
        if self.issuer != *context.authority_key
            || self.claims.deployment_id != context.deployment_id
            || self.claims.space_id != context.space_id
            || self.claims.policy_epoch != context.policy_epoch
        {
            return Err(mismatch("topology update authority or scope differs"));
        }
        current_time(
            self.claims.issued_at_ms,
            self.claims.expires_at_ms,
            context.now_ms,
        )
    }
}

pub fn verify_topology_publisher(
    signed: &SignedTopologyPublisher,
    context: &NetworkVerification<'_>,
    node_id: &str,
    node_public_key: &[u8; 32],
    incarnation: &BootIncarnation,
    route_exports: &[VerifiedNetworkGrant],
) -> Result<VerifiedTopologyPublisher, ContractError> {
    if route_exports.len() > nestlink_protocol::network_topology::MAX_PREFIXES {
        return Err(ContractError::new(
            ErrorCode::CapacityExceeded,
            "too many topology RouteExport proofs",
        ));
    }
    signed.validate()?;
    let claims = TopologyPublisherClaims::decode_canonical(&signed.claims)?;
    verify(
        context.authority_key,
        PUBLISHER,
        &signed.claims,
        &signed.signature,
    )?;
    if claims.node_id != node_id || claims.public_key != *node_public_key {
        return Err(mismatch("topology publisher registered node differs"));
    }
    let route_exports = claims
        .route_export_digests
        .iter()
        .filter_map(|authorization| {
            route_exports
                .iter()
                .find(|grant| grant.digest() == *authorization)
                .cloned()
        })
        .collect();
    let publisher = VerifiedTopologyPublisher {
        claims,
        digest: reference(context.authority_key, PUBLISHER, &signed.claims)?,
        issuer: *context.authority_key,
        route_exports,
    };
    publisher.check_current(context, incarnation)?;
    Ok(publisher)
}

/// Enforces a strictly advancing sequence. Exact duplicate handling belongs to
/// the durable management journal before this call and never renews an ad.
pub fn verify_topology_report(
    signed: &SignedTopologyReport,
    publisher: &VerifiedTopologyPublisher,
    context: &NetworkVerification<'_>,
    incarnation: &BootIncarnation,
    last_sequence: u64,
) -> Result<VerifiedTopologyReport, ContractError> {
    signed.validate()?;
    publisher.check_current(context, incarnation)?;
    let claims = TopologyReport::decode_canonical(&signed.claims)?;
    verify(
        &publisher.claims.public_key,
        REPORT,
        &signed.claims,
        &signed.signature,
    )?;
    let permission = &publisher.claims;
    if claims.deployment_id != context.deployment_id
        || claims.space_id != context.space_id
        || claims.policy_epoch != context.policy_epoch
        || claims.node_id != permission.node_id
        || claims.peer != permission.peer
        || claims.publisher_digest != publisher.digest
        || claims.incarnation != *incarnation
    {
        return Err(mismatch("topology report scope or publisher differs"));
    }
    if claims.sequence <= last_sequence {
        return Err(ContractError::new(
            ErrorCode::ReplayRejected,
            "topology report sequence did not advance",
        ));
    }
    if claims.not_before_ms < permission.scope.not_before_ms
        || claims.expires_at_ms > permission.scope.expires_at_ms
        || claims.neighbors.iter().any(|neighbor| {
            permission
                .allowed_neighbors
                .binary_search(&neighbor.remote)
                .is_err()
        })
        || claims
            .prefixes
            .iter()
            .any(|prefix| !permission.allowed_prefixes.contains(prefix))
    {
        return Err(denied("topology report expands publication permission"));
    }
    current_time(claims.not_before_ms, claims.expires_at_ms, context.now_ms)?;
    Ok(VerifiedTopologyReport {
        digest: reference(&permission.public_key, REPORT, &signed.claims)?,
        claims,
        signature: signed.signature.clone(),
        publisher: publisher.clone(),
    })
}

pub fn verify_topology_advertisement(
    signed: &SignedTopologyAdvertisement,
    publisher: &VerifiedTopologyPublisher,
    context: &NetworkVerification<'_>,
    incarnation: &BootIncarnation,
    last_sequence: u64,
) -> Result<VerifiedTopologyAdvertisement, ContractError> {
    signed.validate()?;
    verify(
        context.authority_key,
        ADVERTISEMENT,
        &signed.claims,
        &signed.signature,
    )?;
    let claims = TopologyAdvertisement::decode_canonical(&signed.claims)?;
    let report = verify_topology_report(
        &SignedTopologyReport {
            claims: claims.report.canonical_bytes()?,
            signature: claims.report_signature.clone(),
        },
        publisher,
        context,
        incarnation,
        last_sequence,
    )?;
    if report.digest != claims.report_digest
        || claims.expires_at_ms > publisher.claims.scope.expires_at_ms
    {
        return Err(mismatch("topology advertisement report reference differs"));
    }
    current_time(claims.not_before_ms, claims.expires_at_ms, context.now_ms)?;
    Ok(VerifiedTopologyAdvertisement {
        claims,
        digest: reference(context.authority_key, ADVERTISEMENT, &signed.claims)?,
        issuer: *context.authority_key,
        envelope_digest: digest(&signed.canonical_bytes()?),
        publisher: publisher.clone(),
    })
}

/// Authenticates the complete full/delta shape, cursor ordering, withdrawals,
/// scope, lifetime and this exact query. Applying it must also compare the saved
/// local cursor; a valid signature is not permission to roll a graph backward.
pub fn verify_topology_update(
    signed: &SignedTopologyUpdate,
    context: &NetworkVerification<'_>,
    expected_nonce: &[u8; 32],
) -> Result<VerifiedTopologyUpdate, ContractError> {
    signed.validate()?;
    verify(
        context.authority_key,
        UPDATE,
        &signed.claims,
        &signed.signature,
    )?;
    let claims = TopologyUpdate::decode_canonical(&signed.claims)?;
    if claims.deployment_id != context.deployment_id
        || claims.space_id != context.space_id
        || claims.policy_epoch != context.policy_epoch
        || claims.query_nonce != *expected_nonce
    {
        return Err(mismatch("topology update scope or query differs"));
    }
    current_time(claims.issued_at_ms, claims.expires_at_ms, context.now_ms)?;
    Ok(VerifiedTopologyUpdate {
        claims,
        digest: reference(context.authority_key, UPDATE, &signed.claims)?,
        issuer: *context.authority_key,
        envelope_digest: digest(&signed.canonical_bytes()?),
    })
}

fn check_scope(scope: &GrantScope, context: &NetworkVerification<'_>) -> Result<(), ContractError> {
    if scope.deployment_id != context.deployment_id || scope.space_id != context.space_id {
        return Err(mismatch("topology publisher space or deployment differs"));
    }
    if scope.policy_epoch != context.policy_epoch
        || context.revoked_grant_ids.contains(&scope.grant_id)
    {
        return Err(ContractError::new(
            ErrorCode::PolicyRevoked,
            "topology publisher policy was revoked",
        ));
    }
    current_time(scope.not_before_ms, scope.expires_at_ms, context.now_ms)
}
fn current_time(start: u64, end: u64, now: u64) -> Result<(), ContractError> {
    if now < start || now >= end {
        return Err(ContractError::new(
            ErrorCode::LeaseExpired,
            "topology statement is outside its lifetime",
        ));
    }
    Ok(())
}
fn message(domain: &[u8], claims: &[u8]) -> Result<Vec<u8>, ContractError> {
    let length: u32 = claims
        .len()
        .try_into()
        .map_err(|_| denied("topology signing message too large"))?;
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(claims);
    Ok(bytes)
}
fn verify(
    key: &[u8; 32],
    domain: &[u8],
    claims: &[u8],
    signature: &[u8],
) -> Result<(), ContractError> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| mismatch("invalid topology issuer key"))?;
    let signature =
        Signature::from_slice(signature).map_err(|_| mismatch("invalid topology signature"))?;
    key.verify_strict(&message(domain, claims)?, &signature)
        .map_err(|_| mismatch("invalid topology signature or purpose"))
}
fn reference(key: &[u8; 32], domain: &[u8], claims: &[u8]) -> Result<[u8; 32], ContractError> {
    let mut bytes = b"NestLink/network-topology/v1/reference\0".to_vec();
    bytes.extend_from_slice(key);
    bytes.extend_from_slice(&message(domain, claims)?);
    Ok(digest(&bytes))
}
fn denied(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::PermissionRequired, reason)
}
fn mismatch(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::IdentityMismatch, reason)
}
