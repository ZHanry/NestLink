//! Independent offline verification and one-process cumulative admission.
//! This primitive grants no legacy permit or relay/node resource authority.
use crate::{digest, domain_message, network::NetworkAuthoritySigner, verify_signature};
use ed25519_dalek::Signer;
use nestlink_protocol::{ContractError, ErrorCode, offline::*};
use rand_core::{OsRng, RngCore};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const DOMAIN: &[u8] = b"NestLink/offline/v1/complete-direct-grant-bundle\0";
const REFERENCE: &[u8] = b"NestLink/offline/v1/complete-direct-grant-reference\0";
const APPROVAL: &[u8] = b"NestLink/offline/v1/exact-endpoint-approval\0";

pub fn offline_draft_digest(
    authority: &[u8; 32],
    claims: &OfflineGrantBundleClaims,
) -> Result<[u8; 32], ContractError> {
    if *authority == [0; 32] {
        return Err(denied(
            "offline approval requires an independently pinned authority",
        ));
    }
    let mut reference = REFERENCE.to_vec();
    reference.extend_from_slice(authority);
    reference.extend_from_slice(&claims.canonical_bytes()?);
    Ok(digest(&reference))
}
fn approval_transcript(endpoint: u8, draft_digest: &[u8; 32]) -> Vec<u8> {
    let mut transcript = vec![endpoint];
    transcript.extend_from_slice(draft_digest);
    transcript
}
impl crate::InstallationIdentity {
    /// The caller separately presents the complete draft and exact digest to
    /// the local user. A logged-in administrator cannot produce this signature.
    pub fn sign_offline_endpoint_approval(
        &self,
        authority: &[u8; 32],
        claims: &OfflineGrantBundleClaims,
        endpoint: u8,
        approved_digest: [u8; 32],
    ) -> Result<OfflineEndpointApproval, ContractError> {
        let member = claims
            .members
            .get(usize::from(endpoint))
            .ok_or_else(|| denied("invalid offline endpoint role"))?;
        let draft_digest = offline_draft_digest(authority, claims)?;
        if member.public_key != self.public_key() || approved_digest != draft_digest {
            return Err(denied(
                "offline endpoint approval differs from the explicit local draft",
            ));
        }
        Ok(OfflineEndpointApproval {
            endpoint,
            draft_digest,
            signature: self
                .key
                .sign(&domain_message(
                    APPROVAL,
                    &approval_transcript(endpoint, &draft_digest),
                ))
                .to_bytes()
                .to_vec(),
        })
    }
}
pub fn verify_offline_endpoint_approvals(
    authority: &[u8; 32],
    claims: &OfflineGrantBundleClaims,
    approvals: &[OfflineEndpointApproval; 2],
) -> Result<(), ContractError> {
    for (index, approval) in approvals.iter().enumerate() {
        if usize::from(approval.endpoint) != index {
            return Err(denied(
                "both distinct offline endpoints must approve the exact complete draft",
            ));
        }
        verify_offline_endpoint_approval(authority, claims, approval)?;
    }
    Ok(())
}

/// Verify one endpoint while the other endpoint's independent review is pending.
pub fn verify_offline_endpoint_approval(
    authority: &[u8; 32], claims: &OfflineGrantBundleClaims, approval: &OfflineEndpointApproval,
) -> Result<(), ContractError> {
    let expected = offline_draft_digest(authority, claims)?;
    let member = claims.members.get(usize::from(approval.endpoint))
        .ok_or_else(|| denied("invalid offline endpoint role"))?;
    if approval.draft_digest != expected || approval.signature.len() != 64 {
        return Err(denied("offline endpoint must approve the exact complete draft"));
    }
    verify_signature(&member.public_key, APPROVAL,
        &approval_transcript(approval.endpoint, &expected), &approval.signature)
}

pub struct OfflineVerification<'a> {
    pub authority: &'a [u8; 32],
    pub deployment_id: &'a str,
    pub space_id: &'a str,
    pub policy_epoch: u64,
    pub security_epoch: u64,
    pub highest_revocation_epoch: u64,
    pub revoked_bundle_ids: &'a BTreeSet<String>,
    pub now_ms: u64,
}

/// Reuse the registered installation's existing device-action signature domain
/// with an independently typed, exact offline consume payload and challenge.
pub fn offline_consume_transcript(
    claims: &OfflineGrantBundleClaims,
    challenge: &management::OfflineConsumeChallenge,
) -> Result<nestlink_protocol::DeviceActionClaims, ContractError> {
    claims.validate()?;
    let member = claims.members.get(usize::from(challenge.endpoint))
        .ok_or_else(|| denied("invalid offline consume endpoint"))?;
    if challenge.bundle_id != claims.bundle_id || challenge.process_nonce != member.process_nonce
        || challenge.challenge == [0; 32] || challenge.expires_at_ms != claims.expires_at_ms {
        return Err(denied("offline consume challenge differs from the original process"));
    }
    let payload = serde_json::to_vec(challenge).map_err(|_| denied("invalid offline consume payload"))?;
    Ok(nestlink_protocol::DeviceActionClaims {
        schema_version: nestlink_protocol::SCHEMA_VERSION,
        action: nestlink_protocol::DeviceAction::Approve as i32,
        deployment_id: claims.deployment_id.clone(), security_epoch: claims.security_epoch,
        account_id: member.account_id.clone(), device_id: member.installation_id.clone(),
        resource_id: claims.bundle_id.clone(), challenge: challenge.challenge.to_vec(),
        payload_sha256: digest(&payload).to_vec(), expires_at_unix_ms: challenge.expires_at_ms,
    })
}

pub struct VerifiedOfflineGrantBundle {
    claims: OfflineGrantBundleClaims,
    digest: [u8; 32],
    issuer: [u8; 32],
}
impl VerifiedOfflineGrantBundle {
    pub fn claims(&self) -> &OfflineGrantBundleClaims {
        &self.claims
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn check_current(&self, context: &OfflineVerification<'_>) -> Result<(), ContractError> {
        let c = &self.claims;
        if self.issuer != *context.authority
            || c.deployment_id != context.deployment_id
            || c.space_id != context.space_id
            || c.policy_epoch != context.policy_epoch
            || c.security_epoch != context.security_epoch
            || c.highest_revocation_epoch != context.highest_revocation_epoch
            || context.revoked_bundle_ids.contains(&c.bundle_id)
        {
            return Err(revoked(
                "offline trust, epoch or received revocation changed",
            ));
        }
        if context.now_ms < c.issued_at_ms || context.now_ms >= c.expires_at_ms {
            return Err(expired());
        }
        Ok(())
    }
}
impl NetworkAuthoritySigner {
    pub fn sign_offline_bundle(
        &self,
        claims: &OfflineGrantBundleClaims,
    ) -> Result<SignedOfflineGrantBundle, ContractError> {
        let claims = claims.canonical_bytes()?;
        Ok(SignedOfflineGrantBundle {
            signature: self
                .key
                .sign(&domain_message(DOMAIN, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
pub fn verify_offline_bundle(
    signed: &SignedOfflineGrantBundle,
    context: &OfflineVerification<'_>,
) -> Result<VerifiedOfflineGrantBundle, ContractError> {
    signed.validate()?;
    verify_signature(context.authority, DOMAIN, &signed.claims, &signed.signature)?;
    let claims = OfflineGrantBundleClaims::decode_canonical(&signed.claims)?;
    let mut reference = REFERENCE.to_vec();
    reference.extend_from_slice(context.authority);
    reference.extend_from_slice(&signed.claims);
    let result = VerifiedOfflineGrantBundle {
        claims,
        digest: digest(&reference),
        issuer: *context.authority,
    };
    result.check_current(context)?;
    Ok(result)
}

/// Keep exactly one of these in the original installation runtime. The nonce
/// is generated in memory; disk state cannot recreate a process activation.
/// Consumed IDs remain burned after the corresponding owner closes.
pub struct OfflineProcess {
    installation_id: String,
    public_key: [u8; 32],
    nonce: [u8; 32],
    consumed: BTreeSet<String>,
    highest_wall_ms: u64,
    highest_revocation_epoch: u64,
    stopped: Arc<AtomicBool>,
}
impl OfflineProcess {
    pub fn new(
        installation_id: String,
        public_key: [u8; 32],
        now_ms: u64,
        highest_revocation_epoch: u64,
    ) -> Result<Self, ContractError> {
        if !nestlink_protocol::valid_id(&installation_id)
            || public_key == [0; 32]
            || now_ms == 0
            || highest_revocation_epoch == 0
        {
            return Err(denied(
                "offline process needs a fixed registered installation",
            ));
        }
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        Ok(Self {
            installation_id,
            public_key,
            nonce,
            consumed: BTreeSet::new(),
            highest_wall_ms: now_ms,
            highest_revocation_epoch,
            stopped: Arc::new(AtomicBool::new(false)),
        })
    }
    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
    /// Only call with a freshly authenticated online policy/consume response.
    /// The storage reservation must already be irrevocably committed. Exact
    /// local consent is a separate requirement, never inferred from the bundle.
    pub fn activate(
        &mut self,
        bundle: VerifiedOfflineGrantBundle,
        context: &OfflineVerification<'_>,
        approved_digest: [u8; 32],
    ) -> Result<OfflineAdmission, ContractError> {
        if self.stopped.load(Ordering::Acquire)
            || context.now_ms < self.highest_wall_ms
            || context.highest_revocation_epoch != self.highest_revocation_epoch
        {
            self.stop();
            return Err(revoked("offline process observed rollback or was stopped"));
        }
        self.highest_wall_ms = context.now_ms;
        self.highest_revocation_epoch = context.highest_revocation_epoch;
        bundle.check_current(context)?;
        let local = bundle
            .claims
            .members
            .iter()
            .position(|m| {
                m.installation_id == self.installation_id
                    && m.public_key == self.public_key
                    && m.process_nonce == self.nonce
            })
            .ok_or_else(|| denied("offline bundle belongs to another process or installation"))?;
        if approved_digest != bundle.digest
            || approved_digest == [0; 32]
            || self.consumed.len() >= 4096
            || !self.consumed.insert(bundle.claims.bundle_id.clone())
        {
            return Err(denied(
                "offline bundle approval changed or original activation was consumed",
            ));
        }
        let remaining = bundle.claims.expires_at_ms - context.now_ms;
        Ok(OfflineAdmission {
            deadline: Instant::now() + Duration::from_millis(remaining),
            highest_wall_ms: context.now_ms,
            highest_revocation_epoch: context.highest_revocation_epoch,
            local,
            bundle,
            process_stopped: self.stopped.clone(),
            spent_bytes: 0,
            written_bytes: 0,
            connections: 0,
            stopped: false,
        })
    }
    /// Local exit/disable is terminal for all future activations in this process.
    /// Already activated admission owners observe this shared terminal flag.
    pub fn stop(&mut self) {
        self.stopped.store(true, Ordering::Release);
    }
}
impl Drop for OfflineProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Unique cumulative budget owner. Reconnecting a carrier reuses this object;
/// it never deserializes, clones, retries activation or refunds a reservation.
pub struct OfflineAdmission {
    bundle: VerifiedOfflineGrantBundle,
    local: usize,
    deadline: Instant,
    highest_wall_ms: u64,
    highest_revocation_epoch: u64,
    spent_bytes: u64,
    written_bytes: u64,
    connections: u32,
    stopped: bool,
    process_stopped: Arc<AtomicBool>,
}
impl OfflineAdmission {
    pub fn claims(&self) -> &OfflineGrantBundleClaims {
        self.bundle.claims()
    }
    pub fn digest(&self) -> [u8; 32] {
        self.bundle.digest()
    }
    pub fn spent_bytes(&self) -> u64 {
        self.spent_bytes
    }
    pub fn written_bytes(&self) -> u64 {
        self.written_bytes
    }
    pub fn connections(&self) -> u32 {
        self.connections
    }
    pub fn is_stopped(&self) -> bool {
        self.stopped || self.process_stopped.load(Ordering::Acquire)
    }
    pub fn remaining_lifetime(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
    pub fn stop(&mut self) {
        self.stopped = true;
    }
    fn check(&mut self, wall_ms: u64) -> Result<(), ContractError> {
        if self.is_stopped() {
            self.stop();
            return Err(revoked("original offline owner is terminal"));
        }
        if wall_ms < self.highest_wall_ms
            || wall_ms >= self.bundle.claims.expires_at_ms
            || Instant::now() >= self.deadline
        {
            self.stop();
            return Err(expired());
        }
        self.highest_wall_ms = wall_ms;
        Ok(())
    }
    /// Call at least once a second even while no application I/O is pending;
    /// the carrier owner closes all channels when this check fails.
    pub fn check_current(&mut self, wall_ms: u64) -> Result<(), ContractError> {
        self.check(wall_ms)
    }
    /// Recovery synchronizes received policy before admitting more offline I/O.
    /// A newer revocation epoch closes this owner, including unrelated changes;
    /// only a new, explicitly approved online reservation may grant new rights.
    pub fn observe_online(
        &mut self,
        context: &OfflineVerification<'_>,
    ) -> Result<(), ContractError> {
        let result = self
            .check(context.now_ms)
            .and_then(|()| self.bundle.check_current(context));
        if result.is_err() || context.highest_revocation_epoch < self.highest_revocation_epoch {
            self.stop();
            return Err(revoked(
                "offline recovery observed changed authority or rollback",
            ));
        }
        self.highest_revocation_epoch = context.highest_revocation_epoch;
        Ok(())
    }
    /// `remote_key` comes from the authenticated TLS/QUIC peer certificate and
    /// endpoint proof, never a discovery entry. No relay path variant exists.
    pub fn admit_connection(
        &mut self,
        wall_ms: u64,
        transport: OfflineDirectTransport,
        remote_key: &[u8; 32],
    ) -> Result<(), ContractError> {
        self.check(wall_ms)?;
        let claims = self.bundle.claims();
        if *remote_key != claims.members[1 - self.local].public_key
            || !claims.connection.direct_transports.contains(&transport)
        {
            return Err(denied(
                "offline connection is not the exact approved direct peer",
            ));
        }
        if self.connections >= claims.resources.connection_limit {
            self.stop();
            return Err(denied(
                "offline cumulative connection reservation exhausted",
            ));
        }
        self.connections += 1;
        Ok(())
    }
    pub fn admit_remote_operation(
        &mut self,
        wall_ms: u64,
        operation: OfflineRemoteOperation,
        bytes: u64,
    ) -> Result<(), ContractError> {
        self.check(wall_ms)?;
        if self.connections == 0 {
            return Err(denied(
                "offline operations require an authenticated direct connection",
            ));
        }
        let OfflineBusiness::RemoteControl { operations, .. } = &self.bundle.claims.business else {
            return Err(denied(
                "offline private service does not grant remote operations",
            ));
        };
        if !operations.contains(&operation) {
            return Err(denied("offline operation was not separately approved"));
        }
        self.charge(
            bytes,
            if operation == OfflineRemoteOperation::FileWrite {
                bytes
            } else {
                0
            },
        )
    }
    pub fn admit_private_service(
        &mut self,
        wall_ms: u64,
        definition_digest: &[u8; 32],
        target_digest: &[u8; 32],
        bytes: u64,
    ) -> Result<(), ContractError> {
        self.check(wall_ms)?;
        if self.connections == 0 {
            return Err(denied(
                "offline operations require an authenticated direct connection",
            ));
        }
        let OfflineBusiness::PrivateService {
            definition_digest: definition,
            target_digest: target,
            ..
        } = &self.bundle.claims.business
        else {
            return Err(denied(
                "offline remote authority does not grant private service access",
            ));
        };
        if definition != definition_digest || target != target_digest {
            return Err(denied("offline private target or definition changed"));
        }
        self.charge(bytes, 0)
    }
    fn charge(&mut self, bytes: u64, written: u64) -> Result<(), ContractError> {
        let spent = self.spent_bytes.checked_add(bytes);
        let files = self.written_bytes.checked_add(written);
        let limits = &self.bundle.claims.resources;
        match (spent, files) {
            (Some(spent), Some(files))
                if spent <= limits.byte_limit && files <= limits.file_write_limit =>
            {
                self.spent_bytes = spent;
                self.written_bytes = files;
                Ok(())
            }
            _ => {
                self.stop();
                Err(denied(
                    "offline original byte or file reservation exhausted",
                ))
            }
        }
    }
}
fn denied(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::PermissionRequired, reason)
}
fn revoked(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::PolicyRevoked, reason)
}
fn expired() -> ContractError {
    ContractError::new(
        ErrorCode::LeaseExpired,
        "offline original deadline or clock anchor expired",
    )
}

#[cfg(test)]
mod tests;
