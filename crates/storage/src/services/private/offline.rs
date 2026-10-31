//! Exact existing private ACL/target policy and original shared quota adaptation.
use super::*;
use nestlink_protocol::offline::{management::OfflinePrivateDraftRequest, *};

pub(crate) struct OfflinePrivateAuthority {
    pub rule_id: String,
    pub exposure_revision: u64,
}

impl Store {
    pub(crate) fn offline_private_draft(
        &self,
        actor: &Principal,
        request: &OfflinePrivateDraftRequest,
        now: u64,
    ) -> Result<(OfflineBusiness, [OfflineMember; 2], OfflinePrivateAuthority), StorageError> {
        let (record, approval, view, binding, acl_end) =
            self.private_consumer(actor, &request.service_id, &request.consumer_device_id, now)?;
        if !self
            .private_service_paths(
                &actor.session_id,
                &request.consumer_device_id,
                &record.definition.host_device_id,
                &record.id,
                now / 1000,
            )?
            .contains(nestlink_protocol::Path::Direct)
            || request.expected_service_revision != record.revision
            || request.expected_exposure_revision != view.revision
            || request.maximum_connections > u32::from(record.definition.limits.maximum_connections)
            || request.maximum_bytes > record.definition.limits.maximum_bytes
            || request.expires_at_ms > acl_end.min(approval.expires)
        {
            return Err(StorageError::Forbidden);
        }
        let host = self.device_record_at(&record.definition.host_device_id, now / 1000)?;
        let members = [
            OfflineMember {
                installation_id: request.consumer_device_id.clone(),
                account_id: actor.account_id.clone(),
                public_key: binding.consumer_public_key,
                membership_epoch: binding.consumer_membership_epoch,
                process_nonce: request.process_nonces[0],
            },
            OfflineMember {
                installation_id: record.definition.host_device_id,
                account_id: host.account,
                public_key: binding.host_public_key,
                membership_epoch: binding.host_membership_epoch,
                process_nonce: request.process_nonces[1],
            },
        ];
        Ok((
            OfflineBusiness::PrivateService {
                service_id: record.id,
                service_revision: record.revision,
                definition_digest: record.hash,
                target_digest: view.target_sha256,
            },
            members,
            OfflinePrivateAuthority {
                rule_id: binding.acl_rule_id,
                exposure_revision: view.revision,
            },
        ))
    }

    pub(crate) fn offline_private_current(
        &self,
        account: &str,
        login: &str,
        claims: &OfflineGrantBundleClaims,
        original: &OfflinePrivateAuthority,
        now: u64,
    ) -> Result<(), StorageError> {
        let OfflineBusiness::PrivateService {
            service_id,
            service_revision,
            definition_digest,
            target_digest,
        } = &claims.business
        else {
            return Err(StorageError::Forbidden);
        };
        let (record, approval, view, binding, acl_end) = self.private_consumer_bound(
            account,
            login,
            service_id,
            &claims.members[0].installation_id,
            now,
        )?;
        if binding.acl_rule_id != original.rule_id
            || view.revision != original.exposure_revision
            || view.space_id != claims.space_id
            || record.revision != *service_revision
            || record.hash != *definition_digest
            || view.target_sha256 != *target_digest
            || record.definition.host_device_id != claims.members[1].installation_id
            || claims.expires_at_ms > acl_end.min(approval.expires)
            || binding.consumer_membership_epoch != claims.members[0].membership_epoch
            || binding.host_membership_epoch != claims.members[1].membership_epoch
            || binding.consumer_public_key != claims.members[0].public_key
            || binding.host_public_key != claims.members[1].public_key
            || binding.consumer_account_id != claims.members[0].account_id
            || record.account != claims.members[1].account_id
            || claims.resources.connection_limit
                > u32::from(record.definition.limits.maximum_connections)
            || !self
                .private_service_paths(
                    login,
                    &claims.members[0].installation_id,
                    &claims.members[1].installation_id,
                    service_id,
                    now / 1000,
                )?
                .contains(nestlink_protocol::Path::Direct)
        {
            return Err(StorageError::Forbidden);
        }
        Ok(())
    }

    pub(crate) fn offline_private_reserve(
        &self,
        tx: &Transaction<'_>,
        claims: &OfflineGrantBundleClaims,
    ) -> Result<(), StorageError> {
        let OfflineBusiness::PrivateService { service_id, .. } = &claims.business else {
            return Err(StorageError::Forbidden);
        };
        let record = self.service_record(service_id)?;
        let view = exposure(tx, service_id)?.ok_or(StorageError::Forbidden)?;
        if mode_available(tx, service_id, true, view.private_maximum_bytes)?
            < claims.resources.byte_limit
        {
            return Err(StorageError::RateLimited);
        }
        Self::reserve_offline_service_budget(tx, &record, claims.resources.byte_limit)?;
        tx.execute("INSERT INTO offline_service_reservations(reservation_id,bundle_id,service_id,promised_bytes) VALUES(?1,?2,?3,?4)",
            params![claims.resources.reservation_id,claims.bundle_id,service_id,claims.resources.byte_limit])?;
        Ok(())
    }
}
