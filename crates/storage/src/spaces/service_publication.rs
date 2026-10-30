//! Space policy intersects independently approved service publishing.
use super::*;
use nestlink_protocol::{
    api::{ServiceApprovalState, ServiceDefinition, ServiceIngress},
    spaces::service_publication::*,
};

const MAX_BINDINGS: u64 = 128;
const MAX_RULES: u64 = 256;
const MAX_RULE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

struct Binding {
    space: String,
    account: String,
    host: String,
    service_revision: u64,
    epoch: u64,
    protocol: SpaceServiceProtocol,
    port: u16,
    revoked: bool,
}

fn protocol_name(protocol: SpaceServiceProtocol) -> &'static str {
    match protocol {
        SpaceServiceProtocol::Http => "http",
        SpaceServiceProtocol::Https => "https",
        SpaceServiceProtocol::Tcp => "tcp",
        SpaceServiceProtocol::Udp => "udp",
    }
}

fn protocol(value: &str) -> Result<SpaceServiceProtocol, StorageError> {
    match value {
        "http" => Ok(SpaceServiceProtocol::Http),
        "https" => Ok(SpaceServiceProtocol::Https),
        "tcp" => Ok(SpaceServiceProtocol::Tcp),
        "udp" => Ok(SpaceServiceProtocol::Udp),
        _ => Err(StorageError::Conflict),
    }
}

fn endpoint(definition: &ServiceDefinition) -> (SpaceServiceProtocol, u16) {
    match &definition.requested_ingress {
        ServiceIngress::Http { .. } => (SpaceServiceProtocol::Http, 80),
        ServiceIngress::Https { .. } => (SpaceServiceProtocol::Https, 443),
        ServiceIngress::Tcp { port } => (SpaceServiceProtocol::Tcp, *port),
        ServiceIngress::Udp { port } => (SpaceServiceProtocol::Udp, *port),
    }
}

fn binding(connection: &Connection, service: &str) -> Result<Option<Binding>, StorageError> {
    type Row = (String, String, String, u64, u64, String, u16, bool);
    let row: Option<Row> = connection.query_row(
        "SELECT space_id,account_id,host_device_id,service_revision,binding_epoch,protocol,port,revoked FROM space_service_bindings WHERE service_id=?1",
        [service], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)),
    ).optional()?;
    row.map(
        |(space, account, host, service_revision, epoch, name, port, revoked)| {
            Ok(Binding {
                space,
                account,
                host,
                service_revision,
                epoch,
                protocol: protocol(&name)?,
                port,
                revoked,
            })
        },
    )
    .transpose()
}

pub(super) fn stop_publications(
    tx: &Transaction<'_>,
    space: &str,
    account: Option<&str>,
    host: Option<&str>,
) -> Result<(), StorageError> {
    tx.execute("UPDATE service_publications SET state=1 WHERE state=0 AND service_id IN
        (SELECT service_id FROM space_service_bindings WHERE space_id=?1 AND (?2 IS NULL OR account_id=?2) AND (?3 IS NULL OR host_device_id=?3))",
        params![space,account,host])?;
    Ok(())
}

fn stop_service(tx: &Transaction<'_>, service: &str) -> Result<(), StorageError> {
    tx.execute(
        "UPDATE service_publications SET state=1 WHERE service_id=?1 AND state=0",
        [service],
    )?;
    Ok(())
}

impl Store {
    fn space_service_host_state(
        &self,
        space: &str,
        account: &str,
        host: &str,
        now: u64,
    ) -> Result<(u64, u64), StorageError> {
        clock(now)?;
        let current: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM network_spaces s JOIN network_authorities a ON a.space_id=s.space_id JOIN deployment d ON d.singleton=1 WHERE s.space_id=?1 AND s.archived=0 AND a.restore_fenced=0 AND a.authority_revoked=0 AND a.security_epoch=d.security_epoch AND a.last_observed_ms<=?2)", params![space,now], |r|r.get(0))?;
        if !current {
            return Err(StorageError::Forbidden);
        }
        let (role, account_epoch, active) = member(&self.connection, space, account)?;
        if !active {
            return Err(StorageError::Forbidden);
        }
        let device = self.device_record_at(host, now / 1000)?;
        if device.account != account {
            return Err(StorageError::Forbidden);
        }
        type HostRow = (Vec<u8>, u64, String, bool, Vec<u8>);
        let row: Option<HostRow> = self.connection.query_row(
            "SELECT m.public_key,m.membership_epoch,m.role,m.revoked,d.key_sha256 FROM network_memberships m JOIN devices d ON d.id=m.installation_id WHERE m.space_id=?1 AND m.installation_id=?2",
            params![space,host], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        ).optional()?;
        let (key, device_epoch, device_role, revoked, key_hash) =
            row.ok_or(StorageError::Forbidden)?;
        if revoked
            || key != device.public_key
            || device_role != role_name(role)
            || key_hash != nestlink_identity::digest(&device.public_key)
        {
            return Err(StorageError::Forbidden);
        }
        Ok((account_epoch, device_epoch))
    }

    /// Existing services with no space binding retain their separate legacy
    /// policy. Once bound, even a revoked binding continues to fence that path.
    pub(crate) fn space_service_publication_deadline(
        &self,
        service: &str,
        revision: u64,
        account: &str,
        definition: &ServiceDefinition,
        now: u64,
    ) -> Result<Option<u64>, StorageError> {
        let Some(bound) = binding(&self.connection, service)? else {
            return Ok(None);
        };
        if bound.revoked
            || bound.account != account
            || bound.host != definition.host_device_id
            || bound.service_revision != revision
            || endpoint(definition) != (bound.protocol, bound.port)
        {
            return Err(StorageError::Forbidden);
        }
        let (account_epoch, host_epoch) =
            self.space_service_host_state(&bound.space, account, &bound.host, now)?;
        let deadline: Option<u64> = self.connection.query_row(
            "SELECT max(expires_at_ms) FROM space_service_rules WHERE service_id=?1 AND space_id=?2 AND binding_epoch=?3
             AND revoked=0 AND expires_at_ms>?4 AND protocol=?5 AND port=?6 AND operation='publish' AND host_membership_epoch=?7
             AND ((subject_kind='account' AND subject_id=?8 AND subject_epoch=?9) OR (subject_kind='device' AND subject_id=?10 AND subject_epoch=?7))",
            params![service,bound.space,bound.epoch,now,protocol_name(bound.protocol),bound.port,host_epoch,account,account_epoch,bound.host], |r|r.get(0),
        )?;
        deadline.map(Some).ok_or(StorageError::Forbidden)
    }

    pub fn space_service_policy(
        &self,
        actor: &Principal,
        space_id: &str,
        now: u64,
    ) -> Result<SpaceServicePolicyView, StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, space_id, now)?;
        let mut query = tx.prepare("SELECT service_id FROM space_service_bindings WHERE space_id=?1 AND (?2 OR account_id=?3) ORDER BY service_id LIMIT ?4")?;
        let ids = query
            .query_map(
                params![
                    space_id,
                    management(space.role),
                    actor.account_id,
                    MAX_BINDINGS + 1
                ],
                |r| r.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        if ids.len() as u64 > MAX_BINDINGS {
            return Err(StorageError::RateLimited);
        }
        let mut bindings = Vec::new();
        for id in ids {
            let bound = binding(&tx, &id)?.ok_or(StorageError::Forbidden)?;
            let current = match self
                .approved_space_service_definition(&id, bound.service_revision, now)
                .and_then(|(account, definition)| {
                    if account != bound.account
                        || definition.host_device_id != bound.host
                        || endpoint(&definition) != (bound.protocol, bound.port)
                    {
                        return Err(StorageError::Forbidden);
                    }
                    self.space_service_host_state(space_id, &bound.account, &bound.host, now)
                }) {
                Ok(state) => Some(state),
                Err(
                    StorageError::Forbidden | StorageError::Unauthorized | StorageError::Conflict,
                ) => None,
                Err(error) => return Err(error),
            };
            type RuleRow = (String, String, String, u64, u64, String, u16, u64, bool);
            let mut query = tx.prepare("SELECT rule_id,subject_kind,subject_id,subject_epoch,host_membership_epoch,protocol,port,expires_at_ms,revoked FROM space_service_rules WHERE space_id=?1 AND service_id=?2 AND binding_epoch=?3 ORDER BY rule_id LIMIT ?4")?;
            let rows = query
                .query_map(params![space_id, id, bound.epoch, MAX_RULES + 1], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                })?
                .collect::<Result<Vec<RuleRow>, _>>()?;
            if rows.len() as u64 > MAX_RULES {
                return Err(StorageError::RateLimited);
            }
            let mut rules = Vec::new();
            for (
                rule_id,
                kind,
                subject_id,
                subject_epoch,
                host_membership_epoch,
                name,
                port,
                expires_at_unix_ms,
                revoked,
            ) in rows
            {
                let subject = match kind.as_str() {
                    "account" => SpaceServiceSubject::Account {
                        account_id: subject_id,
                    },
                    "device" => SpaceServiceSubject::Device {
                        installation_id: subject_id,
                    },
                    _ => return Err(StorageError::Conflict),
                };
                let active = !bound.revoked
                    && !revoked
                    && expires_at_unix_ms > now
                    && current.is_some_and(|(account_epoch, host_epoch)| {
                        host_epoch == host_membership_epoch
                            && match &subject {
                                SpaceServiceSubject::Account { account_id } => {
                                    account_id == &bound.account && subject_epoch == account_epoch
                                }
                                SpaceServiceSubject::Device { installation_id } => {
                                    installation_id == &bound.host && subject_epoch == host_epoch
                                }
                            }
                    });
                rules.push(SpaceServiceRuleView {
                    rule_id,
                    subject,
                    subject_epoch,
                    host_membership_epoch,
                    protocol: protocol(&name)?,
                    port,
                    operation: SpaceServiceOperation::Publish,
                    expires_at_unix_ms,
                    revoked,
                    active,
                });
            }
            bindings.push(SpaceServiceBindingView {
                service_id: id,
                account_id: bound.account,
                host_device_id: bound.host,
                service_revision: bound.service_revision,
                binding_epoch: bound.epoch,
                protocol: bound.protocol,
                port: bound.port,
                revoked: bound.revoked,
                rules,
            });
        }
        Ok(SpaceServicePolicyView { space, bindings })
    }

    pub fn bind_space_service(
        &mut self,
        actor: &Principal,
        space_id: &str,
        service: &str,
        request: SpaceServiceBindingRequest,
        now: u64,
    ) -> Result<SpaceView, StorageError> {
        require_id(service)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, space_id, now)?;
        writable(&space, request.expected_revision)?;
        let view = self.service(actor, service, now / 1000)?;
        if view.revision != request.expected_service_revision {
            return Err(StorageError::Conflict);
        }
        if view.approval != ServiceApprovalState::ApprovedTarget {
            return Err(StorageError::Forbidden);
        }
        self.space_service_host_state(
            space_id,
            &actor.account_id,
            &view.definition.host_device_id,
            now,
        )?;
        let old = binding(&tx, service)?;
        if old.as_ref().is_some_and(|old| old.space != space_id) {
            return Err(StorageError::Forbidden);
        }
        let count: u64 = tx.query_row(
            "SELECT count(*) FROM space_service_bindings WHERE space_id=?1",
            [space_id],
            |r| r.get(0),
        )?;
        if old.is_none() && count >= MAX_BINDINGS {
            return Err(StorageError::RateLimited);
        }
        let epoch = old
            .map_or(0, |old| old.epoch)
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(StorageError::Conflict)?;
        let (protocol, port) = endpoint(&view.definition);
        tx.execute("INSERT INTO space_service_bindings(service_id,space_id,account_id,host_device_id,service_revision,binding_epoch,protocol,port) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
            ON CONFLICT(service_id) DO UPDATE SET account_id=excluded.account_id,host_device_id=excluded.host_device_id,service_revision=excluded.service_revision,binding_epoch=excluded.binding_epoch,protocol=excluded.protocol,port=excluded.port,revoked=0",
            params![service,space_id,actor.account_id,view.definition.host_device_id,view.revision,epoch,protocol_name(protocol),port])?;
        tx.execute(
            "UPDATE space_service_rules SET revoked=1 WHERE service_id=?1",
            [service],
        )?;
        stop_service(&tx, service)?;
        advance(&tx, &space, now)?;
        event(&tx, actor, space_id, "space_service_bound", service, now)?;
        let view = read_space(&tx, actor, space_id, now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn revoke_space_service(
        &mut self,
        actor: &Principal,
        space_id: &str,
        service: &str,
        request: SpaceRevisionRequest,
        now: u64,
    ) -> Result<SpaceView, StorageError> {
        require_id(service)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, space_id, now)?;
        writable(&space, request.expected_revision)?;
        let bound = binding(&tx, service)?
            .filter(|bound| bound.space == space_id)
            .ok_or(StorageError::Forbidden)?;
        if !management(space.role) && bound.account != actor.account_id {
            return Err(StorageError::Forbidden);
        }
        tx.execute(
            "UPDATE space_service_bindings SET revoked=1 WHERE service_id=?1",
            [service],
        )?;
        tx.execute(
            "UPDATE space_service_rules SET revoked=1 WHERE service_id=?1",
            [service],
        )?;
        stop_service(&tx, service)?;
        advance(&tx, &space, now)?;
        event(&tx, actor, space_id, "space_service_revoked", service, now)?;
        let view = read_space(&tx, actor, space_id, now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn grant_space_service_rule(
        &mut self,
        actor: &Principal,
        space_id: &str,
        service: &str,
        request: SpaceServiceRuleRequest,
        now: u64,
    ) -> Result<SpaceView, StorageError> {
        require_id(service)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, space_id, now)?;
        writable(&space, request.expected_revision)?;
        if !management(space.role) {
            return Err(StorageError::Forbidden);
        }
        let bound = binding(&tx, service)?
            .filter(|bound| bound.space == space_id && !bound.revoked)
            .ok_or(StorageError::Forbidden)?;
        if bound.epoch != request.expected_binding_epoch {
            return Err(StorageError::Conflict);
        }
        let (account, definition) =
            self.approved_space_service_definition(service, bound.service_revision, now)?;
        if account != bound.account
            || definition.host_device_id != bound.host
            || endpoint(&definition) != (bound.protocol, bound.port)
        {
            return Err(StorageError::Forbidden);
        }
        if request.protocol != bound.protocol
            || request.port != bound.port
            || request.operation != SpaceServiceOperation::Publish
        {
            return Err(StorageError::Forbidden);
        }
        if request.expires_at_unix_ms <= now
            || request.expires_at_unix_ms > i64::MAX as u64
            || request.expires_at_unix_ms - now > MAX_RULE_MS
        {
            return Err(StorageError::Invalid(
                "publication rule must expire within seven days",
            ));
        }
        let (account_epoch, host_epoch) =
            self.space_service_host_state(space_id, &bound.account, &bound.host, now)?;
        let (kind, subject, epoch) = match &request.subject {
            SpaceServiceSubject::Account { account_id } if account_id == &bound.account => {
                ("account", account_id, account_epoch)
            }
            SpaceServiceSubject::Device { installation_id } if installation_id == &bound.host => {
                ("device", installation_id, host_epoch)
            }
            _ => return Err(StorageError::Forbidden),
        };
        tx.execute("DELETE FROM space_service_rules WHERE service_id=?1 AND (revoked=1 OR expires_at_ms<=?2 OR binding_epoch<>?3)",params![service,now,bound.epoch])?;
        let count: u64 = tx.query_row(
            "SELECT count(*) FROM space_service_rules WHERE service_id=?1",
            [service],
            |r| r.get(0),
        )?;
        if count >= MAX_RULES {
            return Err(StorageError::RateLimited);
        }
        let rule = random_id();
        tx.execute("INSERT INTO space_service_rules(rule_id,space_id,service_id,binding_epoch,subject_kind,subject_id,subject_epoch,host_membership_epoch,protocol,port,operation,expires_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'publish',?11)",params![rule,space_id,service,bound.epoch,kind,subject,epoch,host_epoch,protocol_name(bound.protocol),bound.port,request.expires_at_unix_ms])?;
        advance(&tx, &space, now)?;
        event(
            &tx,
            actor,
            space_id,
            "space_service_rule_granted",
            &rule,
            now,
        )?;
        let view = read_space(&tx, actor, space_id, now)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn revoke_space_service_rule(
        &mut self,
        actor: &Principal,
        space_id: &str,
        service: &str,
        rule: &str,
        request: SpaceRevisionRequest,
        now: u64,
    ) -> Result<SpaceView, StorageError> {
        require_id(service)?;
        require_id(rule)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.validate_access(actor, now / 1000)?;
        let space = read_space(&tx, actor, space_id, now)?;
        writable(&space, request.expected_revision)?;
        if !management(space.role) {
            return Err(StorageError::Forbidden);
        }
        if tx.execute("UPDATE space_service_rules SET revoked=1 WHERE space_id=?1 AND service_id=?2 AND rule_id=?3",params![space_id,service,rule])? != 1 { return Err(StorageError::Forbidden); }
        stop_service(&tx, service)?;
        advance(&tx, &space, now)?;
        event(
            &tx,
            actor,
            space_id,
            "space_service_rule_revoked",
            rule,
            now,
        )?;
        let view = read_space(&tx, actor, space_id, now)?;
        tx.commit()?;
        Ok(view)
    }
}
