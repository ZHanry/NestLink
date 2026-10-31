//! Private consumer ACLs and installation report ownership. All reservations
//! and spend use the existing four service quota ledgers.
use super::*;
use nestlink_identity::{service_plane::ServiceLeaseSigner, services::private::*};
use nestlink_protocol::{SCHEMA_VERSION, service_plane::*, services::private::*};
use rusqlite::{Connection, Transaction, TransactionBehavior};

const MAX_RULE_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAX_RULES: u64 = 256;
mod network;
mod offline;
pub(crate) use offline::OfflinePrivateAuthority;
mod relay;

fn mode(value: &str) -> Result<ServiceAccessMode, StorageError> {
    match value {
        "private" => Ok(ServiceAccessMode::Private),
        "public" => Ok(ServiceAccessMode::Public),
        "both" => Ok(ServiceAccessMode::Both),
        _ => Err(StorageError::Conflict),
    }
}
fn mode_name(value: ServiceAccessMode) -> &'static str {
    match value {
        ServiceAccessMode::Private => "private",
        ServiceAccessMode::Public => "public",
        ServiceAccessMode::Both => "both",
    }
}
fn exposure(
    connection: &Connection,
    service: &str,
) -> Result<Option<ServiceExposureView>, StorageError> {
    type Row = (u64, u64, Vec<u8>, String, String, u64, u64);
    let row: Option<Row> = connection.query_row("SELECT revision,service_revision,target_sha256,space_id,mode,private_bytes,public_bytes FROM service_exposures WHERE service_id=?1",[service],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional()?;
    row.map(
        |(
            revision,
            service_revision,
            target,
            space_id,
            name,
            private_maximum_bytes,
            public_maximum_bytes,
        )| {
            Ok(ServiceExposureView {
                service_id: service.into(),
                revision,
                service_revision,
                target_sha256: target.try_into().map_err(|_| StorageError::Conflict)?,
                space_id,
                mode: mode(&name)?,
                private_maximum_bytes,
                public_maximum_bytes,
            })
        },
    )
    .transpose()
}
/// Includes all historical spend and every unsealed promise, including revoked
/// or expired runtimes. Changing modes does not replenish either sublimit.
fn mode_available(
    connection: &Connection,
    service: &str,
    private: bool,
    maximum: u64,
) -> Result<u64, StorageError> {
    let held: u64 = connection.query_row("SELECT COALESCE(SUM(CASE WHEN g.terminal=1 THEN g.admitted_bytes ELSE g.grant_bytes END),0) FROM service_usage_grants g WHERE g.service_id=?1 AND EXISTS(SELECT 1 FROM private_service_leases p WHERE p.grant_id=g.grant_id)=?2",params![service,private],|r|r.get(0))?;
    let offline: u64 = if private {
        connection.query_row("SELECT COALESCE(SUM(promised_bytes),0) FROM offline_service_reservations WHERE service_id=?1", [service], |r| r.get(0))?
    } else {
        0
    };
    let held = held.checked_add(offline).ok_or(StorageError::Conflict)?;
    Ok(maximum.saturating_sub(held))
}
pub(super) fn public_reservation_limit(
    connection: &Connection,
    record: &Record,
) -> Result<u64, StorageError> {
    if record.definition.edge_node_id.is_empty() {
        return Err(StorageError::Forbidden);
    }
    let maximum = if let Some(view) = exposure(connection, &record.id)? {
        if !view.mode.public_enabled() || view.service_revision != record.revision {
            return Err(StorageError::Forbidden);
        }
        view.public_maximum_bytes
    } else {
        return Ok(record.definition.limits.maximum_bytes);
    };
    mode_available(connection, &record.id, false, maximum)
}
fn clock(now: u64) -> Result<(), StorageError> {
    if now == 0 || now > i64::MAX as u64 {
        return Err(StorageError::Invalid("invalid private service clock"));
    }
    Ok(())
}
fn account_epoch(
    connection: &Connection,
    space: &str,
    account: &str,
    now: u64,
) -> Result<u64, StorageError> {
    let epoch: Option<u64> = connection.query_row("SELECT m.member_epoch FROM network_space_members m JOIN network_spaces s ON s.space_id=m.space_id JOIN network_authorities a ON a.space_id=s.space_id JOIN deployment d ON d.singleton=1 JOIN accounts ac ON ac.id=m.account_id WHERE m.space_id=?1 AND m.account_id=?2 AND m.revoked=0 AND s.archived=0 AND ac.disabled=0 AND a.restore_fenced=0 AND a.authority_revoked=0 AND a.security_epoch=d.security_epoch AND a.last_observed_ms<=?3",params![space,account,now],|r|r.get(0)).optional()?;
    epoch.ok_or(StorageError::Forbidden)
}
impl Store {
    fn private_member(
        &self,
        space: &str,
        device: &str,
        now: u64,
    ) -> Result<(String, u64, u64, [u8; 32]), StorageError> {
        let current = self.device_record_at(device, now / 1000)?;
        let account = account_epoch(&self.connection, space, &current.account, now)?;
        let row: Option<(u64,Vec<u8>)> = self.connection.query_row("SELECT membership_epoch,public_key FROM network_memberships WHERE space_id=?1 AND installation_id=?2 AND revoked=0",params![space,device],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (membership, key) = row.ok_or(StorageError::Forbidden)?;
        if key.as_slice() != current.public_key {
            return Err(StorageError::Forbidden);
        }
        Ok((current.account, account, membership, current.public_key))
    }
    fn private_exposure_current(
        &self,
        service: &str,
        now: u64,
    ) -> Result<(Record, Approval, ServiceExposureView, u64), StorageError> {
        clock(now)?;
        let record = self.service_record(service)?;
        let approval = self
            .service_approval_row(service)?
            .ok_or(StorageError::Forbidden)?;
        let view = exposure(&self.connection, service)?.ok_or(StorageError::Forbidden)?;
        if !view.mode.private_enabled()
            || view.service_revision != record.revision
            || view.target_sha256.as_slice() != approval.target_hash.as_slice()
            || !self.service_approval_live(&record, &approval, now / 1000)?
            || approval.expires <= now
        {
            return Err(StorageError::Forbidden);
        }
        let (account, _, host_epoch, _) =
            self.private_member(&view.space_id, &record.definition.host_device_id, now)?;
        if account != record.account {
            return Err(StorageError::Forbidden);
        }
        Ok((record, approval, view, host_epoch))
    }
    pub fn service_exposure(
        &self,
        actor: &Principal,
        service: &str,
        now: u64,
    ) -> Result<Option<ServiceExposureView>, StorageError> {
        self.service_owner(actor, service, now / 1000)?;
        exposure(&self.connection, service)
    }
    pub fn set_service_exposure(
        &mut self,
        actor: &Principal,
        service: &str,
        request: ServiceExposureUpdate,
        now: u64,
    ) -> Result<ServiceExposureView, StorageError> {
        clock(now)?;
        require_id(&request.space_id)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let record = self.service_owner(actor, service, now / 1000)?;
        let approval = self
            .service_approval_row(service)?
            .ok_or(StorageError::Forbidden)?;
        if request.mode.public_enabled() && record.definition.edge_node_id.is_empty() {
            return Err(StorageError::Invalid(
                "public access requires a registered public edge",
            ));
        }
        if request.expected_service_revision != record.revision {
            return Err(StorageError::Conflict);
        }
        if !self.service_approval_live(&record, &approval, now / 1000)? || approval.expires <= now {
            return Err(StorageError::Forbidden);
        }
        let (_, _, _, _) =
            self.private_member(&request.space_id, &record.definition.host_device_id, now)?;
        if request.mode.private_enabled() != (request.private_maximum_bytes > 0)
            || request.mode.public_enabled() != (request.public_maximum_bytes > 0)
            || request
                .private_maximum_bytes
                .checked_add(request.public_maximum_bytes)
                .is_none_or(|n| n > record.definition.limits.maximum_bytes)
        {
            return Err(StorageError::Invalid(
                "service mode sublimits exceed original cumulative budget",
            ));
        }
        let old = exposure(&tx, service)?;
        if old.as_ref().map_or(0, |v| v.revision) != request.expected_revision {
            return Err(StorageError::Conflict);
        }
        let revision = request
            .expected_revision
            .checked_add(1)
            .filter(|n| revision_valid(*n))
            .ok_or(StorageError::Conflict)?;
        tx.execute("INSERT INTO service_exposures(service_id,revision,service_revision,target_sha256,space_id,mode,private_bytes,public_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(service_id) DO UPDATE SET revision=excluded.revision,service_revision=excluded.service_revision,target_sha256=excluded.target_sha256,space_id=excluded.space_id,mode=excluded.mode,private_bytes=excluded.private_bytes,public_bytes=excluded.public_bytes",params![service,revision,record.revision,approval.target_hash,request.space_id,mode_name(request.mode),request.private_maximum_bytes,request.public_maximum_bytes])?;
        tx.execute(
            "UPDATE private_service_acl SET revoked=1 WHERE service_id=?1",
            [service],
        )?;
        tx.execute(
            "UPDATE private_service_leases SET revoked=1 WHERE service_id=?1",
            [service],
        )?;
        tx.execute(
            "DELETE FROM private_service_hosts WHERE service_id=?1",
            [service],
        )?;
        tx.execute(
            "UPDATE service_publications SET state=1 WHERE service_id=?1 AND state=0",
            [service],
        )?;
        auditing::record(
            &tx,
            "service_exposure_changed",
            service,
            auditing::management(actor),
        )?;
        let view = exposure(&tx, service)?.ok_or(StorageError::Conflict)?;
        tx.commit()?;
        Ok(view)
    }
    pub fn private_service_policy(
        &self,
        actor: &Principal,
        service: &str,
        now: u64,
    ) -> Result<PrivateServicePolicyView, StorageError> {
        self.service_owner(actor, service, now / 1000)?;
        let view = exposure(&self.connection, service)?.ok_or(StorageError::Forbidden)?;
        let mut q = self.connection.prepare("SELECT rule_id,subject_kind,subject_id,subject_epoch,host_epoch,expires_at,revoked FROM private_service_acl WHERE service_id=?1 AND exposure_revision=?2 ORDER BY rule_id LIMIT 257")?;
        let rows = q
            .query_map(params![service, view.revision], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, u64>(3)?,
                    r.get::<_, u64>(4)?,
                    r.get::<_, u64>(5)?,
                    r.get::<_, bool>(6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if rows.len() > MAX_RULES as usize {
            return Err(StorageError::RateLimited);
        }
        let mut rules = Vec::new();
        for (
            rule_id,
            kind,
            id,
            subject_epoch,
            host_membership_epoch,
            expires_at_unix_ms,
            revoked,
        ) in rows
        {
            let subject = match kind.as_str() {
                "account" => PrivateServiceSubject::Account { account_id: id },
                "installation" => PrivateServiceSubject::Installation {
                    installation_id: id,
                },
                _ => return Err(StorageError::Conflict),
            };
            rules.push(PrivateServiceAclView {
                rule_id,
                subject,
                subject_epoch,
                host_membership_epoch,
                expires_at_unix_ms,
                revoked,
            });
        }
        Ok(PrivateServicePolicyView {
            exposure: view,
            rules,
        })
    }
    pub fn grant_private_service(
        &mut self,
        actor: &Principal,
        service: &str,
        request: PrivateServiceAclUpdate,
        now: u64,
    ) -> Result<PrivateServicePolicyView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.service_owner(actor, service, now / 1000)?;
        let (_, _, view, host_epoch) = self.private_exposure_current(service, now)?;
        if request.expected_exposure_revision != view.revision {
            return Err(StorageError::Conflict);
        }
        if request
            .expires_at_unix_ms
            .checked_sub(now)
            .is_none_or(|n| n == 0 || n > MAX_RULE_MS)
            || request.expires_at_unix_ms > i64::MAX as u64
        {
            return Err(StorageError::Invalid(
                "private service ACL must expire within seven days",
            ));
        }
        let (kind, id, epoch) = match &request.subject {
            PrivateServiceSubject::Account { account_id } => {
                require_id(account_id)?;
                (
                    "account",
                    account_id.clone(),
                    account_epoch(&tx, &view.space_id, account_id, now)?,
                )
            }
            PrivateServiceSubject::Installation { installation_id } => {
                require_id(installation_id)?;
                let (_, _, epoch, _) = self.private_member(&view.space_id, installation_id, now)?;
                ("installation", installation_id.clone(), epoch)
            }
        };
        tx.execute("DELETE FROM private_service_acl WHERE service_id=?1 AND (revoked=1 OR expires_at<=?2) AND NOT EXISTS(SELECT 1 FROM private_service_leases l WHERE l.acl_rule_id=private_service_acl.rule_id)",params![service,now])?;
        let count: u64 = tx.query_row(
            "SELECT count(*) FROM private_service_acl WHERE service_id=?1",
            [service],
            |r| r.get(0),
        )?;
        if count >= MAX_RULES {
            return Err(StorageError::RateLimited);
        }
        let rule = random_id();
        tx.execute("INSERT INTO private_service_acl(rule_id,service_id,exposure_revision,subject_kind,subject_id,subject_epoch,host_epoch,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![rule,service,view.revision,kind,id,epoch,host_epoch,request.expires_at_unix_ms])?;
        auditing::record(
            &tx,
            "private_service_acl_granted",
            &rule,
            auditing::management(actor),
        )?;
        tx.commit()?;
        self.private_service_policy(actor, service, now)
    }
    pub fn revoke_private_service(
        &mut self,
        actor: &Principal,
        service: &str,
        rule: &str,
        expected: u64,
        now: u64,
    ) -> Result<PrivateServicePolicyView, StorageError> {
        require_id(rule)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.service_owner(actor, service, now / 1000)?;
        if exposure(&tx, service)?.is_none_or(|v| v.revision != expected) {
            return Err(StorageError::Conflict);
        }
        if tx.execute(
            "UPDATE private_service_acl SET revoked=1 WHERE service_id=?1 AND rule_id=?2",
            params![service, rule],
        )? != 1
        {
            return Err(StorageError::Forbidden);
        }
        tx.execute(
            "UPDATE private_service_leases SET revoked=1 WHERE service_id=?1 AND acl_rule_id=?2",
            params![service, rule],
        )?;
        auditing::record(
            &tx,
            "private_service_acl_revoked",
            rule,
            auditing::management(actor),
        )?;
        tx.commit()?;
        self.private_service_policy(actor, service, now)
    }
    fn private_consumer(
        &self,
        actor: &Principal,
        service: &str,
        consumer: &str,
        now: u64,
    ) -> Result<
        (
            Record,
            Approval,
            ServiceExposureView,
            PrivateServiceClaims,
            u64,
        ),
        StorageError,
    > {
        self.validate_access(actor, now / 1000)?;
        self.private_consumer_bound(&actor.account_id, &actor.session_id, service, consumer, now)
    }
    fn private_consumer_bound(
        &self,
        account_id: &str,
        login: &str,
        service: &str,
        consumer: &str,
        now: u64,
    ) -> Result<
        (
            Record,
            Approval,
            ServiceExposureView,
            PrivateServiceClaims,
            u64,
        ),
        StorageError,
    > {
        if !self.service_login_live(account_id, login, now / 1000)? {
            return Err(StorageError::Forbidden);
        }
        let (record, approval, view, host_epoch) = self.private_exposure_current(service, now)?;
        let (account, account_epoch, consumer_epoch, consumer_key) =
            self.private_member(&view.space_id, consumer, now)?;
        if account != account_id || consumer == record.definition.host_device_id {
            return Err(StorageError::Forbidden);
        }
        if self
            .private_service_paths(
                login,
                consumer,
                &record.definition.host_device_id,
                service,
                now / 1000,
            )?
            .is_empty()
        {
            return Err(StorageError::Forbidden);
        }
        let rule:Option<(String,u64,u64)> = self.connection.query_row("SELECT rule_id,subject_epoch,expires_at FROM private_service_acl WHERE service_id=?1 AND exposure_revision=?2 AND revoked=0 AND host_epoch=?3 AND expires_at>?4 AND ((subject_kind='account' AND subject_id=?5 AND subject_epoch=?6) OR (subject_kind='installation' AND subject_id=?7 AND subject_epoch=?8)) ORDER BY expires_at DESC,rule_id LIMIT 1",params![service,view.revision,host_epoch,now,account,account_epoch,consumer,consumer_epoch],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let (acl_rule_id, subject_epoch, end) = rule.ok_or(StorageError::Forbidden)?;
        let (_, _, _, host_public_key) =
            self.private_member(&view.space_id, &record.definition.host_device_id, now)?;
        let (space_policy_epoch, network_authority_key): (u64, Vec<u8>) =
            self.connection.query_row(
                "SELECT policy_epoch,public_key FROM network_authorities WHERE space_id=?1",
                [&view.space_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
        let network_authority_key = network_authority_key
            .try_into()
            .map_err(|_| StorageError::Conflict)?;
        let claims = PrivateServiceClaims {
            schema_version: SCHEMA_VERSION,
            service_lease_sha256: [0; 32],
            usage_grant_sha256: [0; 32],
            space_id: view.space_id.clone(),
            space_policy_epoch,
            network_authority_key,
            exposure_revision: view.revision,
            acl_rule_id,
            subject_epoch,
            host_membership_epoch: host_epoch,
            consumer_membership_epoch: consumer_epoch,
            consumer_account_id: account,
            consumer_login_id: login.into(),
            consumer_device_id: consumer.into(),
            consumer_public_key: consumer_key,
            host_public_key,
        };
        Ok((record, approval, view, claims, end))
    }
    pub fn private_services(
        &self,
        actor: &Principal,
        consumer: &str,
        query: ServiceQuery,
        now: u64,
    ) -> Result<PrivateServicePage, StorageError> {
        clock(now)?;
        require_id(consumer)?;
        self.validate_access(actor, now / 1000)?;
        if query.security_epoch != self.security_epoch()? || !(1..=100).contains(&query.limit) {
            return Err(StorageError::Conflict);
        }
        if let Some(after) = &query.after_id {
            require_id(after)?;
        }
        let device = self.device_record_at(consumer, now / 1000)?;
        if device.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        let mut q=self.connection.prepare("SELECT service_id FROM service_exposures WHERE service_id>?1 ORDER BY service_id LIMIT 4097")?;
        let ids = q
            .query_map([query.after_id.as_deref().unwrap_or("")], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if ids.len() > 4096 {
            return Err(StorageError::RateLimited);
        }
        let mut entries = Vec::new();
        for id in ids {
            let (record, _, exposure, _, _) = match self.private_consumer(actor, &id, consumer, now)
            {
                Ok(v) => v,
                Err(
                    StorageError::Forbidden | StorageError::Unauthorized | StorageError::Conflict,
                ) => continue,
                Err(e) => return Err(e),
            };
            let ready:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM private_service_hosts WHERE service_id=?1 AND expires_at>?2)",params![id,now],|r|r.get(0))?;
            let availability = if !ready {
                PrivateServiceAvailability::Offline
            } else if mode_available(&self.connection, &id, true, exposure.private_maximum_bytes)?
                == 0
            {
                PrivateServiceAvailability::QuotaExceeded
            } else {
                PrivateServiceAvailability::Ready
            };
            entries.push(PrivateServiceEntry {
                service: self.service_view_record(record, now / 1000)?,
                exposure,
                availability,
            });
            if entries.len() > usize::from(query.limit) {
                break;
            }
        }
        let more = entries.len() > usize::from(query.limit);
        entries.truncate(usize::from(query.limit));
        let next_id = if more {
            entries.last().map(|v| v.service.id.clone())
        } else {
            None
        };
        Ok(PrivateServicePage {
            security_epoch: self.security_epoch()?,
            entries,
            next_id,
            more,
        })
    }
    pub fn register_private_service_host(
        &mut self,
        actor: &Principal,
        signed: &SignedPrivateServiceHost,
        now: u64,
    ) -> Result<(), StorageError> {
        let untrusted: PrivateServiceHostClaims =
            decode_service_message(&signed.claims, PRIVATE_SERVICE_MESSAGE_BYTES)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.service_owner(actor, &untrusted.service_id, now / 1000)?;
        let (record, approval, view, _) =
            self.private_exposure_current(&untrusted.service_id, now)?;
        let key = self
            .device_record_at(&record.definition.host_device_id, now / 1000)?
            .public_key;
        let c = verify_private_service_host(signed, &key)?;
        if c.deployment_id != self.deployment_id()?
            || c.security_epoch != self.security_epoch()?
            || c.policy_revision != self.policy()?.0
            || c.service_revision != record.revision
            || c.exposure_revision != view.revision
            || c.target_sha256.as_slice() != approval.target_hash.as_slice()
            || c.host_device_id != record.definition.host_device_id
            || now < c.issued_at_unix_ms
            || now >= c.expires_at_unix_ms
            || c.expires_at_unix_ms > approval.expires
        {
            return Err(StorageError::Forbidden);
        }
        let old:Option<(String,u64,Vec<u8>,u64)>=tx.query_row("SELECT runtime_id,request_sequence,claims_sha256,expires_at FROM private_service_hosts WHERE service_id=?1",[&c.service_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        if let Some((runtime, sequence, hash, end)) = old {
            if runtime == c.runtime_id
                && sequence == c.request_sequence
                && hash.as_slice() == digest(&signed.claims)
            {
                return Ok(());
            }
            if runtime == c.runtime_id && c.request_sequence <= sequence
                || runtime != c.runtime_id && end > now
            {
                return Err(StorageError::Conflict);
            }
        }
        tx.execute("INSERT INTO private_service_hosts(service_id,runtime_id,request_sequence,claims_sha256,claims_json,expires_at) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(service_id) DO UPDATE SET runtime_id=excluded.runtime_id,request_sequence=excluded.request_sequence,claims_sha256=excluded.claims_sha256,claims_json=excluded.claims_json,expires_at=excluded.expires_at",params![c.service_id,c.runtime_id,c.request_sequence,digest(&signed.claims),serde_json::to_string(&c)?,c.expires_at_unix_ms])?;
        tx.commit()?;
        Ok(())
    }
    pub fn withdraw_private_service_host(
        &mut self,
        actor: &Principal,
        signed: &SignedPrivateServiceHostWithdrawal,
        now: u64,
    ) -> Result<(), StorageError> {
        let untrusted: PrivateServiceHostClaims =
            decode_service_message(&signed.claims, PRIVATE_SERVICE_MESSAGE_BYTES)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let record = self.service_owner(actor, &untrusted.service_id, now / 1000)?;
        let key = self
            .device_record_at(&record.definition.host_device_id, now / 1000)?
            .public_key;
        let c = verify_private_service_host_withdrawal(signed, &key)?;
        if c.deployment_id != self.deployment_id()?
            || c.security_epoch != self.security_epoch()?
            || c.host_device_id != record.definition.host_device_id
            || now < c.issued_at_unix_ms
            || now >= c.expires_at_unix_ms
        {
            return Err(StorageError::Forbidden);
        }
        tx.execute("DELETE FROM private_service_hosts WHERE service_id=?1 AND runtime_id=?2 AND request_sequence<?3",
            params![c.service_id,c.runtime_id,c.request_sequence])?;
        tx.execute(
            "UPDATE private_service_leases SET revoked=1 WHERE service_id=?1 AND runtime_id=?2",
            params![c.service_id, c.runtime_id],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn issue_private_service(
        &mut self,
        actor: &Principal,
        service: &str,
        request: PrivateServiceAccessRequest,
        signer: &ServiceLeaseSigner,
        now: u64,
    ) -> Result<SignedPrivateServiceLease, StorageError> {
        if !matches!(&request.route, PrivateServiceRouteRequest::Direct) {
            return Err(StorageError::Forbidden);
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let lease =
            self.issue_private_service_in_transaction(&tx, actor, service, request, signer, now)?;
        tx.commit()?;
        Ok(lease)
    }
    fn issue_private_service_in_transaction(
        &self,
        tx: &Transaction<'_>,
        actor: &Principal,
        service: &str,
        request: PrivateServiceAccessRequest,
        signer: &ServiceLeaseSigner,
        now: u64,
    ) -> Result<SignedPrivateServiceLease, StorageError> {
        require_id(&request.request_id)?;
        let request_hash = digest(&serde_json::to_vec(&request)?);
        let (record, approval, view, mut binding, acl_end) =
            self.private_consumer(actor, service, &request.consumer_device_id, now)?;
        let selected = match &request.route {
            PrivateServiceRouteRequest::Direct => nestlink_protocol::Path::Direct,
            PrivateServiceRouteRequest::Relay { .. } => nestlink_protocol::Path::Relay,
        };
        if !self
            .private_service_paths(
                &actor.session_id,
                &request.consumer_device_id,
                &record.definition.host_device_id,
                service,
                now / 1000,
            )?
            .contains(selected)
        {
            return Err(StorageError::Forbidden);
        }
        if request.expected_service_revision != record.revision
            || request.expected_exposure_revision != view.revision
        {
            return Err(StorageError::Conflict);
        }
        let old:Option<(String,String,Vec<u8>)>=tx.query_row("SELECT service_id,grant_id,request_sha256 FROM private_service_leases WHERE request_id=?1",[&request.request_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((original_service, grant, hash)) = old {
            if original_service != service || hash.as_slice() != request_hash {
                return Err(StorageError::Conflict);
            }
            return self.private_service_lease(actor, service, &grant, signer, now);
        }
        let host:Option<String>=tx.query_row("SELECT claims_json FROM private_service_hosts WHERE service_id=?1 AND expires_at>?2",params![service,now],|r|r.get(0)).optional()?;
        let host: PrivateServiceHostClaims =
            serde_json::from_str(&host.ok_or(StorageError::Conflict)?)?;
        if host.service_revision != record.revision
            || host.exposure_revision != view.revision
            || host.target_sha256 != view.target_sha256
        {
            return Err(StorageError::Forbidden);
        }
        let budget = request.maximum_bytes.min(mode_available(
            tx,
            service,
            true,
            view.private_maximum_bytes,
        )?);
        let publication = random_id();
        let usage = Self::reserve_service_usage(
            tx,
            signer,
            &record,
            &approval,
            &publication,
            1,
            &host.runtime_id,
            1,
            view.revision,
            budget,
            now,
        )?;
        let claims = ServiceLeaseClaims {
            edge_group: None,
            schema_version: SCHEMA_VERSION,
            deployment_id: self.deployment_id()?,
            security_epoch: self.security_epoch()?,
            policy_revision: self.policy()?.0,
            publication_id: publication.clone(),
            publication_generation: 1,
            service_id: service.into(),
            service_revision: record.revision,
            choice_revision: record
                .revision
                .checked_sub(1)
                .ok_or(StorageError::Conflict)?,
            account_id: record.account.clone(),
            creator_login_id: record.login.clone(),
            approving_login_id: approval.login.clone(),
            definition: record.definition.clone(),
            definition_sha256: record.hash,
            host_key_sha256: digest(&binding.host_public_key),
            target_id: approval.target.clone(),
            target_sha256: view.target_sha256,
            edge_key_sha256: digest(&binding.host_public_key),
            edge_service_address: host.address,
            edge_runtime_id: host.runtime_id.clone(),
            edge_runtime_generation: 1,
            ingress_claim_id: publication,
            ingress_claim_revision: view.revision,
            usage_grant: usage.clone(),
            lease_sequence: 1,
            issued_at_unix_ms: now,
            expires_at_unix_ms: now
                .checked_add(SERVICE_LEASE_MS)
                .ok_or(StorageError::Conflict)?
                .min(host.expires_at_unix_ms)
                .min(acl_end)
                .min(approval.expires),
        };
        let lease = signer.sign(&claims)?;
        binding.service_lease_sha256 = digest(&lease.claims);
        binding.usage_grant_sha256 = digest(&usage.claims);
        let signed = signer.sign_private_service(lease, &binding)?;
        let grant: ServiceUsageBudgetGrantClaims =
            decode_service_message(&usage.claims, SERVICE_USAGE_BYTES)?;
        tx.execute("INSERT INTO private_service_leases(grant_id,service_id,space_id,exposure_revision,acl_rule_id,host_device_id,host_epoch,runtime_id,consumer_device_id,request_id,request_sha256,lease_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",params![grant.grant_id,service,view.space_id,view.revision,binding.acl_rule_id,record.definition.host_device_id,binding.host_membership_epoch,host.runtime_id,request.consumer_device_id,request.request_id,request_hash,serde_json::to_string(&signed)?])?;
        auditing::record(
            tx,
            "private_service_access_issued",
            &grant.grant_id,
            auditing::management(actor),
        )?;
        Ok(signed)
    }
    /// Used by the actual host/consumer monitor, not just the directory UI.
    pub fn private_service_lease(
        &self,
        actor: &Principal,
        service: &str,
        grant: &str,
        signer: &ServiceLeaseSigner,
        now: u64,
    ) -> Result<SignedPrivateServiceLease, StorageError> {
        require_id(grant)?;
        self.validate_access(actor, now / 1000)?;
        let signed = self.private_service_lease_current(service, grant, signer, now)?;
        let verified = verify_private_service_lease(&signed, &signer.public_key())?;
        if actor.account_id != verified.lease().claims().account_id
            && actor.account_id != verified.claims().consumer_account_id
        {
            return Err(StorageError::Forbidden);
        }
        Ok(signed)
    }
    pub(crate) fn private_service_lease_current(
        &self,
        service: &str,
        grant: &str,
        signer: &ServiceLeaseSigner,
        now: u64,
    ) -> Result<SignedPrivateServiceLease, StorageError> {
        let row:Option<(String,String)>=self.connection.query_row("SELECT l.lease_json,l.consumer_device_id FROM private_service_leases l JOIN service_usage_grants g ON g.grant_id=l.grant_id WHERE l.service_id=?1 AND l.grant_id=?2 AND l.revoked=0 AND g.terminal=0",params![service,grant],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (json, consumer) = row.ok_or(StorageError::Forbidden)?;
        let signed: SignedPrivateServiceLease = serde_json::from_str(&json)?;
        let verified = verify_private_service_lease(&signed, &signer.public_key())?;
        verified.check_time(now)?;
        // Validate the consumer's current membership and exact captured rule;
        // no stale bearer principal is fabricated for this path.
        let (_, _, view, host_epoch) = self.private_exposure_current(service, now)?;
        let (account, account_epoch, consumer_epoch, key) =
            self.private_member(&view.space_id, &consumer, now)?;
        let c = verified.claims();
        if !self.service_login_live(&c.consumer_account_id, &c.consumer_login_id, now / 1000)?
            || !self
                .private_service_paths(
                    &c.consumer_login_id,
                    &consumer,
                    &verified.lease().claims().definition.host_device_id,
                    service,
                    now / 1000,
                )?
                .contains(self.private_service_selected_path(grant)?)
        {
            return Err(StorageError::Forbidden);
        }
        let active:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM private_service_acl WHERE rule_id=?1 AND service_id=?2 AND exposure_revision=?3 AND revoked=0 AND expires_at>?4 AND host_epoch=?5 AND subject_epoch=?6 AND ((subject_kind='account' AND subject_id=?7 AND subject_epoch=?8) OR (subject_kind='installation' AND subject_id=?9 AND subject_epoch=?10)))",params![c.acl_rule_id,service,view.revision,now,host_epoch,c.subject_epoch,account,account_epoch,consumer,consumer_epoch],|r|r.get(0))?;
        let epoch: u64 = self.connection.query_row(
            "SELECT policy_epoch FROM network_authorities WHERE space_id=?1",
            [&view.space_id],
            |r| r.get(0),
        )?;
        if !active
            || c.consumer_account_id != account
            || c.host_membership_epoch != host_epoch
            || c.consumer_membership_epoch != consumer_epoch
            || c.consumer_public_key != key
            || c.exposure_revision != view.revision
            || c.space_policy_epoch != epoch
        {
            return Err(StorageError::Forbidden);
        }
        Ok(signed)
    }
    pub fn accept_private_service_usage(
        &mut self,
        signed: &SignedPrivateServiceUsage,
        now: u64,
    ) -> Result<PrivateServiceUsageAck, StorageError> {
        clock(now)?;
        let untrusted: PrivateServiceUsageClaims =
            decode_service_message(&signed.claims, PRIVATE_SERVICE_MESSAGE_BYTES)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        type Row = (
            String,
            String,
            String,
            u64,
            String,
            String,
            Vec<u8>,
            u64,
            u64,
            u64,
            u64,
            u64,
            Vec<u8>,
            bool,
            u64,
            u64,
        );
        let row:Option<Row>=tx.query_row("SELECT g.account_id,g.host_device_id,g.service_id,l.host_epoch,l.space_id,l.runtime_id,g.grant_sha256,g.grant_bytes,g.admitted_bytes,g.opened_connections,g.closed_connections,g.report_sequence,g.report_sha256,g.terminal,g.sampled_at,g.maximum_connections FROM service_usage_grants g JOIN private_service_leases l ON l.grant_id=g.grant_id WHERE g.grant_id=?1",[&untrusted.grant_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?,r.get(15)?))).optional()?;
        let (
            account,
            host,
            service,
            host_epoch,
            space,
            runtime,
            hash,
            ceiling,
            admitted,
            opened,
            closed,
            sequence,
            report_hash,
            terminal,
            sampled,
            max_connections,
        ) = row.ok_or(StorageError::Forbidden)?;
        let (_, _, current_epoch, key) = self.private_member(&space, &host, now)?;
        let c = verify_private_service_usage(signed, &key)?;
        let report_digest = digest(&signed.claims);
        if c.deployment_id != self.deployment_id()?
            || c.security_epoch != self.security_epoch()?
            || current_epoch != host_epoch
            || c.host_device_id != host
            || c.runtime_id != runtime
            || c.grant_sha256.as_slice() != hash.as_slice()
            || c.sampled_at_unix_ms > now
        {
            return Err(StorageError::Forbidden);
        }
        if c.report_sequence == sequence && report_digest.as_slice() == report_hash.as_slice() {
            let json:String=tx.query_row("SELECT ack_json FROM private_service_usage_reports WHERE grant_id=?1 AND report_sequence=?2",params![c.grant_id,sequence],|r|r.get(0))?;
            return Ok(serde_json::from_str(&json)?);
        }
        if terminal
            || c.report_sequence != sequence.checked_add(1).ok_or(StorageError::Conflict)?
            || c.admitted_bytes < admitted
            || c.admitted_bytes > ceiling
            || c.opened_connections < opened
            || c.closed_connections < closed
            || c.opened_connections - c.closed_connections > max_connections
            || c.sampled_at_unix_ms < sampled
        {
            return Err(StorageError::Conflict);
        }
        let delta = c.admitted_bytes - admitted;
        let node: String = tx.query_row(
            "SELECT node_id FROM service_usage_grants WHERE grant_id=?1",
            [&c.grant_id],
            |r| r.get(0),
        )?;
        for (scope, key) in [
            ("account", account.as_str()),
            ("device", host.as_str()),
            ("node", node.as_str()),
            ("resource", service.as_str()),
        ] {
            Self::add_scope_spend(&tx, scope, key, delta)?;
        }
        let ack = PrivateServiceUsageAck {
            grant_id: c.grant_id.clone(),
            report_sequence: c.report_sequence,
            report_sha256: report_digest,
            terminal: c.terminal,
        };
        tx.execute("INSERT INTO private_service_usage_reports(grant_id,report_sequence,report_sha256,report_json,ack_json) VALUES(?1,?2,?3,?4,?5)",params![c.grant_id,c.report_sequence,report_digest,serde_json::to_string(signed)?,serde_json::to_string(&ack)?])?;
        if tx.execute("UPDATE service_usage_grants SET admitted_bytes=?1,opened_connections=?2,closed_connections=?3,report_sequence=?4,report_sha256=?5,sampled_at=?6,terminal=?7 WHERE grant_id=?8 AND report_sequence=?9 AND terminal=0",params![c.admitted_bytes,c.opened_connections,c.closed_connections,c.report_sequence,report_digest,c.sampled_at_unix_ms,c.terminal,c.grant_id,sequence])?!=1 {return Err(StorageError::Conflict);}
        tx.commit()?;
        Ok(ack)
    }
}
