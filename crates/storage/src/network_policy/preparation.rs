//! Narrow product-space preparation for the two devices of current consent.
//! Stored membership IDs are deterministic and cannot be replaced after loss,
//! expiry or revocation. Preparation grants neither a path nor business access.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::network::remote_preparation_grant_ids;
use nestlink_protocol::{Path, api::NetworkRemotePreparationRequest};
use prost::Message;

const PREPARATION_MS: u64 = 60_000;

pub struct NetworkRemotePreparationBundle {
    pub request_id: String,
    pub binding: NetworkRemotePreparationRequest,
    pub snapshot: TrustedNetworkPolicySnapshot,
    pub memberships: [SignedNetworkGrant; 2],
    pub issued_at_ms: u64,
}

impl Store {
    /// Exactly one transaction intersects active product membership, approved
    /// business participants, current device keys and both existing epochs.
    pub fn prepare_network_remote(
        &mut self,
        actor: &Principal,
        signer: &NetworkAuthoritySigner,
        space: &str,
        request: &str,
        binding: NetworkRemotePreparationRequest,
        now_ms: u64,
    ) -> Result<NetworkRemotePreparationBundle, StorageError> {
        self.network_remote_preparation_transaction(actor, Some(signer), space, request, binding, now_ms)
    }

    /// Read the same committed pair after response loss. This never signs or
    /// renews, including when either original credential has been revoked.
    pub fn network_remote_preparation(
        &mut self,
        actor: &Principal,
        space: &str,
        request: &str,
        binding: NetworkRemotePreparationRequest,
        now_ms: u64,
    ) -> Result<NetworkRemotePreparationBundle, StorageError> {
        self.network_remote_preparation_transaction(actor, None, space, request, binding, now_ms)
    }

    fn network_remote_preparation_transaction(
        &self,
        actor: &Principal,
        signer: Option<&NetworkAuthoritySigner>,
        space: &str,
        request: &str,
        binding: NetworkRemotePreparationRequest,
        now_ms: u64,
    ) -> Result<NetworkRemotePreparationBundle, StorageError> {
        let ids = remote_preparation_grant_ids(space, request, &binding)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, checked_seconds(now_ms)?)?;
        // remote() is participant-account scoped even for a global admin.
        self.remote(actor, request)?;
        let product_space = crate::spaces::read_space(&tx, actor, space, now_ms)?;
        if product_space.archived {
            return Err(StorageError::Forbidden);
        }
        let business = remote_paths::current_business(self, request, now_ms)?;
        if business.connection_generation != binding.connection_generation
            || URL_SAFE_NO_PAD.encode(digest(&business.encode_to_vec())) != binding.permit_sha256
            || !business.paths.iter().any(|path| [Path::Direct as i32, Path::Relay as i32].contains(path))
        {
            return Err(StorageError::Forbidden);
        }
        let snapshot = read_snapshot(&tx, space, now_ms)?;
        if snapshot.revision != binding.expected_space_revision
            || snapshot.policy_epoch != binding.expected_policy_epoch
        {
            return Err(StorageError::Conflict);
        }
        let installations = [&business.controller_device_id, &business.host_device_id];
        if installations[0] == installations[1] {
            return Err(StorageError::Forbidden);
        }
        let mut epochs = [0; 2];
        let mut expires = business.expires_at_unix_ms.min(now_ms.saturating_add(PREPARATION_MS));
        for (index, installation) in installations.iter().enumerate() {
            let member = snapshot.members.get(*installation).filter(|m| m.active)
                .ok_or(StorageError::Forbidden)?;
            let expected_key = if index == 0 { &business.controller_key_sha256 } else { &business.host_key_sha256 };
            if digest(&member.public_key).as_slice() != expected_key.as_slice() {
                return Err(StorageError::Forbidden);
            }
            epochs[index] = member.membership_epoch;
            if let Some(end) = self.device_expiration_ms(installation)? {
                expires = expires.min(end);
            }
        }
        let exists: [bool; 2] = [
            tx.query_row("SELECT EXISTS(SELECT 1 FROM network_grants WHERE space_id=?1 AND grant_id=?2)", params![space, ids[0]], |r| r.get(0))?,
            tx.query_row("SELECT EXISTS(SELECT 1 FROM network_grants WHERE space_id=?1 AND grant_id=?2)", params![space, ids[1]], |r| r.get(0))?,
        ];
        if exists == [false, false] {
            let signer = signer.ok_or(StorageError::Forbidden)?;
            if expires <= now_ms {
                return Err(StorageError::Forbidden);
            }
            for index in 0..2 {
                self.issue_network_membership_in_transaction(
                    &tx, actor, signer,
                    NetworkMembershipRequest {
                        space_id: space.into(),
                        installation_id: installations[index].clone(),
                        grant_id: ids[index].clone(),
                        expected_policy_epoch: binding.expected_policy_epoch,
                        expected_membership_epoch: epochs[index],
                        expires_at_ms: expires,
                    },
                    &snapshot, true, now_ms,
                )?;
            }
        } else if exists != [true, true] {
            // A partial pair or an unrelated collision cannot mint its sibling.
            return Err(StorageError::Forbidden);
        }
        let (controller, c) = remote_paths::member_credential(&tx, &snapshot, &ids[0], installations[0])?;
        let (host, h) = remote_paths::member_credential(&tx, &snapshot, &ids[1], installations[1])?;
        let scope = &c.claims().scope;
        if scope.not_before_ms != h.claims().scope.not_before_ms
            || scope.expires_at_ms != h.claims().scope.expires_at_ms
            || scope.expires_at_ms > business.expires_at_unix_ms
            || scope.expires_at_ms > expires
            || scope.expires_at_ms.saturating_sub(scope.not_before_ms) > PREPARATION_MS
        {
            return Err(StorageError::Forbidden);
        }
        let issued_at_ms = scope.not_before_ms;
        observe(&tx, space, now_ms)?;
        tx.commit()?;
        Ok(NetworkRemotePreparationBundle {
            request_id: request.into(), binding, snapshot,
            memberships: [controller, host], issued_at_ms,
        })
    }
}
