//! A direct successor is an exact, durable child of a still-live signed path.
//! The unchanged dual-signed business receipt does not itself grant space I/O.
use super::*;
use crate::reconnection::ReconnectionReceipt;
use nestlink_identity::{reconnection, verify_device_action};
use nestlink_protocol::{PermitClaims, api::ReconnectionSubmission};

const PARENT_LIMIT: usize = 64;
const MAX_DEPTH: usize = 16;

pub(super) struct Lineage {
    parent: String,
    fingerprint: [u8; 32],
    receipt: ReconnectionReceipt,
    depth: usize,
    expires: u64,
}
fn fingerprint(bundle: &NetworkRemotePathBundle) -> [u8; 32] {
    reconnection::direct_recovery_fingerprint(
        &bundle.path.claims,
        &bundle.connectivity.claims,
        [&bundle.memberships[0].claims, &bundle.memberships[1].claims],
    )
}
fn same_scope(a: &NetworkRemotePathBundle, b: &NetworkRemotePathBundle) -> bool {
    let a_scope = &a.verified.claims().scope;
    let b_scope = &b.verified.claims().scope;
    a.request_id == b.request_id
        && a.memberships.iter().zip(&b.memberships).all(|(a, b)| {
            a.claims == b.claims && a.signature == b.signature
        })
        && a_scope.deployment_id == b_scope.deployment_id
        && a_scope.space_id == b_scope.space_id
        && a_scope.policy_epoch == b_scope.policy_epoch
        && a_scope.expires_at_ms == b_scope.expires_at_ms
        && a.verified.claims().policy == b.verified.claims().policy
}
impl Lineage {
    pub(super) fn insert(
        self,
        tx: &Transaction<'_>,
        space: &str,
        path: &str,
    ) -> Result<(), StorageError> {
        tx.execute(
            "INSERT INTO network_direct_recovery_lineage VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![space,path,self.parent,serde_json::to_string(&self.receipt.previous)?,
                serde_json::to_string(&self.receipt.next)?,serde_json::to_string(&self.receipt.submission)?,
                self.fingerprint.as_slice(),self.depth,self.expires],
        )?;
        Ok(())
    }
}
impl Store {
    fn verify_direct_transition(
        &self,
        previous: &PermitClaims,
        next: &PermitClaims,
        submission: &ReconnectionSubmission,
        now: u64,
    ) -> Result<(), StorageError> {
        reconnection::validate_successor(previous, next, &submission.choice)?;
        if submission.choice.network_recovery.is_some() || now >= previous.expires_at_unix_ms {
            return Err(StorageError::Forbidden);
        }
        for (device, key_digest, signature) in [
            (&previous.controller_device_id, &previous.controller_key_sha256, &submission.controller_signature),
            (&previous.host_device_id, &previous.host_key_sha256, &submission.host_signature),
        ] {
            let device_record = self.device_record_at(device, now / 1000)?;
            if digest(&device_record.public_key).as_slice() != key_digest.as_slice() {
                return Err(StorageError::Forbidden);
            }
            verify_device_action(
                &reconnection::transcript(previous, device, &submission.choice)?,
                &device_record.public_key,
                &crate::control::decode_signature(signature)?,
            )?;
        }
        Ok(())
    }

    pub(super) fn direct_recovery_lineage(
        &self,
        tx: &Transaction<'_>,
        business: &PermitClaims,
        space: &str,
        request: &NetworkRemotePathRequest,
        now: u64,
    ) -> Result<Option<Lineage>, StorageError> {
        let Some(receipt) = self.receipt(&business.session_id)? else {
            return Ok(None);
        };
        if receipt.next != *business {
            return Ok(None);
        }
        self.verify_direct_transition(&receipt.previous, &receipt.next, &receipt.submission, now)?;
        let previous_digest = digest(&receipt.previous.encode_to_vec());
        // The dedicated index confines this to one space/session/generation.
        // Overflow fails closed rather than scanning arbitrary stored grants.
        let mut query = tx.prepare("SELECT path_grant_id FROM network_remote_paths WHERE space_id=?1 AND request_id=?2 AND business_digest=?3 ORDER BY path_grant_id LIMIT ?4")?;
        let parents = query.query_map(
            params![space,business.session_id,previous_digest.as_slice(),PARENT_LIMIT + 1],
            |row| row.get::<_, String>(0),
        )?.collect::<Result<Vec<_>, _>>()?;
        if parents.len() > PARENT_LIMIT {
            return Err(StorageError::RateLimited);
        }
        let mut matched = None;
        for id in parents {
            let parent = match self.network_path_current_with_business(
                tx, None, space, &id, (0, 0), now, Some(&receipt.previous),
            ) {
                Ok(parent) => parent,
                Err(StorageError::Forbidden) => continue,
                Err(error) => return Err(error),
            };
            let hash = fingerprint(&parent);
            if request.path_grant_id != reconnection::direct_recovery_id(
                &receipt.previous, &receipt.submission.choice, hash, 1,
            )? || request.connectivity_grant_id != reconnection::direct_recovery_id(
                &receipt.previous, &receipt.submission.choice, hash, 2,
            )? {
                continue;
            }
            let depth = self.validate_direct_lineage(tx, space, &parent, &receipt.previous, now)? + 1;
            let scope = &parent.verified.claims().scope;
            let members: (String, String) = tx.query_row(
                "SELECT controller_membership_id,host_membership_id FROM network_remote_paths WHERE space_id=?1 AND path_grant_id=?2",
                params![space,id], |row| Ok((row.get(0)?,row.get(1)?)),
            )?;
            if matched.is_some() || depth > MAX_DEPTH
                || request.controller_membership_grant_id != members.0
                || request.host_membership_grant_id != members.1
                || request.expected_policy_epoch != scope.policy_epoch
                || request.expires_at_unix_ms != scope.expires_at_ms
            {
                return Err(StorageError::Forbidden);
            }
            matched = Some((id, hash, depth, scope.expires_at_ms));
        }
        let (parent, fingerprint, depth, expires) = matched.ok_or(StorageError::Forbidden)?;
        Ok(Some(Lineage { parent, fingerprint, receipt, depth, expires }))
    }

    /// Validate each historically verified business transition only as ancestry.
    /// No historical permit is ever returned as current business authority.
    pub(super) fn validate_direct_lineage(
        &self,
        tx: &Transaction<'_>,
        space: &str,
        child: &NetworkRemotePathBundle,
        business: &PermitClaims,
        now: u64,
    ) -> Result<usize, StorageError> {
        let mut id = child.verified.claims().scope.grant_id.clone();
        let mut expected = business.clone();
        let mut remaining = None;
        let mut total = 0;
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(id.clone()) || seen.len() > MAX_DEPTH + 1 {
                return Err(StorageError::Forbidden);
            }
            type Row = (String, String, String, String, Vec<u8>, usize, u64);
            let row: Option<Row> = tx.query_row(
                "SELECT parent_path_grant_id,previous_permit_json,next_permit_json,submission_json,parent_fingerprint,depth,expires_at_ms FROM network_direct_recovery_lineage WHERE space_id=?1 AND path_grant_id=?2",
                params![space,id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
            ).optional()?;
            let Some((parent_id, previous, next, submission, hash, depth, expires)) = row else {
                if remaining.is_some_and(|depth| depth != 0)
                    || (remaining.is_none() && self.receipt(&business.session_id)?.is_some_and(|receipt| receipt.next == *business))
                {
                    return Err(StorageError::Forbidden);
                }
                return Ok(total);
            };
            let previous: PermitClaims = serde_json::from_str(&previous)?;
            let next: PermitClaims = serde_json::from_str(&next)?;
            let submission: ReconnectionSubmission = serde_json::from_str(&submission)?;
            self.verify_direct_transition(&previous, &next, &submission, now)?;
            if next != expected || previous.session_id != child.request_id
                || submission.choice.network_recovery.is_some()
                || depth == 0 || depth > MAX_DEPTH
                || remaining.is_some_and(|expected| expected != depth)
                || expires != child.verified.claims().scope.expires_at_ms || now >= expires
            {
                return Err(StorageError::Forbidden);
            }
            let parent = self.network_path_current_with_business(
                tx, None, space, &parent_id, (0, 0), now, Some(&previous),
            )?;
            let actual_hash = fingerprint(&parent);
            if hash != actual_hash || !same_scope(child, &parent)
                || id != reconnection::direct_recovery_id(&previous, &submission.choice, actual_hash, 1)?
            {
                return Err(StorageError::Forbidden);
            }
            let connectivity_id: String = tx.query_row(
                "SELECT connectivity_grant_id FROM network_remote_paths WHERE space_id=?1 AND path_grant_id=?2",
                params![space,id], |row| row.get(0),
            )?;
            if connectivity_id != reconnection::direct_recovery_id(&previous, &submission.choice, actual_hash, 2)? {
                return Err(StorageError::Forbidden);
            }
            if remaining.is_none() { total = depth; }
            remaining = Some(depth - 1);
            expected = previous;
            id = parent_id;
        }
    }
}
