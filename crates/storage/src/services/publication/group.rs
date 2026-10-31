//! One approved service, immutable per-edge slices, and the original durable
//! accounting primitive. A failed member cannot donate an unsealed promise.
use super::*;
use nestlink_identity::service_plane::group::service_edge_group_digest;
use nestlink_protocol::service_plane::group::*;

pub struct ServiceGroupPublicationIssue {
    pub group: ServiceEdgeGroupView,
    pub members: Vec<ServicePublicationIssue>,
}
fn advance(value: u64) -> Result<u64, StorageError> {
    value.checked_add(1).filter(|next|revision_valid(*next)).ok_or(StorageError::Conflict)
}

fn configured(connection: &rusqlite::Connection, service: &str) -> Result<Option<(ServiceEdgeGroupView, bool)>, StorageError> {
    type GroupRow = (String, String, u64, u64, Vec<u8>, bool);
    let row: Option<GroupRow> = connection.query_row(
        "SELECT view_json,group_id,revision,service_revision,aggregate_sha256,revoked FROM service_edge_groups WHERE service_id=?1",
        [service], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
    ).optional()?;
    row.map(|(json,id,revision,service_revision,hash,revoked)| {
        let view: ServiceEdgeGroupView = serde_json::from_str(&json)?;
        if view.service_id != service || view.group_id != id || view.revision != revision
            || view.service_revision != service_revision || service_edge_group_digest(&view)?.as_slice() != hash {
            return Err(StorageError::Conflict);
        }
        Ok((view,revoked))
    }).transpose()
}

fn namespace_keys(record: &Record, group: &ServiceEdgeGroupView) -> Vec<String> {
    match &record.definition.requested_ingress {
        ServiceIngress::Http {hostname} | ServiceIngress::Https {hostname} => vec![format!("web:{hostname}")],
        ServiceIngress::Tcp {port} => group.public_ips.iter().map(|ip|format!("front-tcp:{ip}:{port}")).collect(),
        ServiceIngress::Udp {port} => group.public_ips.iter().map(|ip|format!("front-udp:{ip}:{port}")).collect(),
    }
}
fn member_ingress_key(record: &Record, node: &str) -> String {
    match &record.definition.requested_ingress {
        ServiceIngress::Http {hostname} | ServiceIngress::Https {hostname} => format!("web:{node}:{hostname}"),
        ingress => ingress_key(node,ingress),
    }
}

pub(super) fn single_ingress_available(tx: &Transaction<'_>, record: &Record, now: u64) -> Result<(), StorageError> {
    let grouped: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM service_publications WHERE service_id=?1 AND edge_group_id IS NOT NULL AND state IN(0,1))",
        [&record.id], |r|r.get(0))?;
    let held: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM service_edge_group_ingress WHERE ingress_key=?1 AND promised_until>?2)",
        params![ingress_key(&record.definition.edge_node_id,&record.definition.requested_ingress),now], |r|r.get(0))?;
    if grouped || held { return Err(StorageError::RateLimited); }
    Ok(())
}

impl Store {
    fn group_service_facts(&self, id: &str, now: u64) -> Result<(Record, Approval), StorageError> {
        let record = self.service_record(id)?;
        let approval = self.service_approval_row(id)?.ok_or(StorageError::Forbidden)?;
        if !self.service_approval_live(&record,&approval,now/1000)? || now >= approval.expires
            || record.definition.edge_node_id.is_empty() || record.definition.allowed_sources.is_empty() {
            return Err(StorageError::Forbidden);
        }
        self.space_service_publication_deadline(id,record.revision,&record.account,&record.definition,now)?;
        Ok((record,approval))
    }
    fn current_service_group(&self, record: &Record, approval: &Approval) -> Result<ServiceEdgeGroupView, StorageError> {
        let (view,revoked) = configured(&self.connection,&record.id)?.ok_or(StorageError::Forbidden)?;
        view.validate(&record.definition)?;
        if revoked || view.service_revision != record.revision || view.definition_sha256 != record.hash
            || view.target_sha256.as_slice() != approval.target_hash.as_slice() {
            return Err(StorageError::Forbidden);
        }
        // A crashed edge may lose its runtime lease without invalidating the
        // other members. Registration, roles and namespace changes do invalidate
        // the whole original group; no recovery can silently change recipients.
        for member in &view.members {
            let roles: Option<String> = self.connection.query_row(
                "SELECT roles_json FROM data_nodes WHERE id=?1 AND revoked=0",[&member.node_id],|r|r.get(0)).optional()?;
            let roles: Vec<i32> = serde_json::from_str(&roles.ok_or(StorageError::Forbidden)?)?;
            let namespace = self.service_namespace_current(&member.node_id)?;
            if !roles.contains(&(NodeRole::NodeEdge as i32)) || namespace.revision != member.namespace_revision
                || !namespace.config.permits(&record.definition.requested_ingress) {
                return Err(StorageError::Forbidden);
            }
        }
        Ok(view)
    }
    pub fn service_edge_group(&self, actor: &Principal, id: &str, now: u64) -> Result<ServiceEdgeGroupView, StorageError> {
        self.service_owner(actor,id,now/1000)?;
        let (record,approval) = self.group_service_facts(id,now)?;
        self.current_service_group(&record,&approval)
    }
    pub fn set_service_edge_group(&mut self, actor: &Principal, id: &str, update: ServiceEdgeGroupUpdate, now: u64) -> Result<ServiceEdgeGroupView, StorageError> {
        let tx = Transaction::new_unchecked(&self.connection,rusqlite::TransactionBehavior::Immediate)?;
        let record = self.service_owner(actor,id,now/1000)?;
        if record.revision != update.expected_service_revision { return Err(StorageError::Conflict); }
        let (record,approval) = self.group_service_facts(id,now)?;
        update.validate(&record.definition)?;
        let old = configured(&tx,id)?;
        if old.as_ref().map_or(0,|(view,_)|view.revision) != update.expected_revision { return Err(StorageError::Conflict); }
        for member in &update.members {
            let edge = self.service_edge_live(&member.node_id,now)?;
            if edge.namespace.revision != member.namespace_revision || !edge.namespace.config.permits(&record.definition.requested_ingress) {
                return Err(StorageError::Forbidden);
            }
        }
        let view = ServiceEdgeGroupView {group_version:SERVICE_EDGE_GROUP_VERSION,
            group_id:old.map_or_else(random_id,|(view,_)|view.group_id),revision:advance(update.expected_revision)?,
            service_id:id.into(),service_revision:record.revision,definition_sha256:record.hash,
            target_sha256:approval.target_hash.try_into().map_err(|_|StorageError::Conflict)?,
            public_ips:update.public_ips,members:update.members};
        view.validate(&record.definition)?;
        let hash = service_edge_group_digest(&view)?;
        tx.execute("INSERT INTO service_edge_groups(service_id,group_id,revision,service_revision,view_json,aggregate_sha256) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(service_id) DO UPDATE SET revision=excluded.revision,service_revision=excluded.service_revision,view_json=excluded.view_json,aggregate_sha256=excluded.aggregate_sha256,revoked=0",
            params![id,view.group_id,view.revision,view.service_revision,serde_json::to_string(&view)?,hash.as_slice()])?;
        tx.execute("UPDATE service_publications SET state=1 WHERE service_id=?1 AND state=0",[id])?;
        auditing::record(&tx,"service_edge_group_changed",id,auditing::management(actor))?;
        tx.commit()?;
        Ok(view)
    }
    pub fn revoke_service_edge_group(&mut self, actor: &Principal, id: &str, expected_revision: u64, now: u64) -> Result<(), StorageError> {
        let tx = Transaction::new_unchecked(&self.connection,rusqlite::TransactionBehavior::Immediate)?;
        self.service_owner(actor,id,now/1000)?;
        let (view,revoked) = configured(&tx,id)?.ok_or(StorageError::Forbidden)?;
        if view.revision != expected_revision { return Err(StorageError::Conflict); }
        if !revoked {
            tx.execute("UPDATE service_edge_groups SET revoked=1 WHERE service_id=?1",[id])?;
            tx.execute("UPDATE service_publications SET state=1 WHERE service_id=?1 AND state=0",[id])?;
            auditing::record(&tx,"service_edge_group_revoked",id,auditing::management(actor))?;
        }
        tx.commit()?;
        Ok(())
    }
    fn reserve_group_namespace(&self, tx: &Transaction<'_>, record: &Record, view: &ServiceEdgeGroupView, promised: u64, now: u64) -> Result<(), StorageError> {
        for key in namespace_keys(record,view) {
            let old: Option<(String,String,u64)> = tx.query_row("SELECT service_id,group_id,promised_until FROM service_edge_group_ingress WHERE ingress_key=?1",[&key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            if old.is_some_and(|(service,group,until)| until>now && (service!=record.id || group!=view.group_id)) {
                return Err(StorageError::Conflict);
            }
            let single: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM service_publications WHERE ingress_key=?1 AND state IN(0,1))",[&key],|r|r.get(0))?;
            if single { return Err(StorageError::Conflict); }
            tx.execute("INSERT INTO service_edge_group_ingress(ingress_key,service_id,group_id,promised_until) VALUES(?1,?2,?3,?4) ON CONFLICT(ingress_key) DO UPDATE SET service_id=excluded.service_id,group_id=excluded.group_id,promised_until=CASE WHEN service_edge_group_ingress.group_id=excluded.group_id THEN MAX(service_edge_group_ingress.promised_until,excluded.promised_until) ELSE excluded.promised_until END",
                params![key,record.id,view.group_id,promised])?;
        }
        Ok(())
    }
    pub(super) fn group_member_claims(&self, old: &ServiceLeaseClaims, now: u64, sequence: u64) -> Result<(ServiceLeaseClaims, [u8;32]),StorageError> {
        let binding = old.edge_group.as_ref().ok_or(StorageError::Forbidden)?;
        let (record,approval) = self.group_service_facts(&old.service_id,now)?;
        let view = self.current_service_group(&record,&approval)?;
        if view != binding.group || service_edge_group_digest(&view)? != binding.aggregate_sha256 { return Err(StorageError::Forbidden); }
        let member = view.member(&binding.member_node_id)?;
        let edge = self.service_edge_live(&member.node_id,now)?;
        let claims = self.make_service_claims(&record,&approval,&edge,PublicationVersion {
            id:old.publication_id.clone(),generation:old.publication_generation,sequence,
            usage_grant:old.usage_grant.clone(),edge_group:Some(binding.clone()),
        },now)?;
        if publication_binding(old)? != publication_binding(&claims)? { return Err(StorageError::Forbidden); }
        Ok((claims,edge.key))
    }
    pub fn publish_service_group(&mut self, life: &ServiceLifecycle, actor: &Principal, id: &str, request: ServiceGroupPublicationRequest, signer: &ServiceLeaseSigner, now: u64) -> Result<ServiceGroupPublicationIssue, StorageError> {
        request.validate()?;
        let tx = Transaction::new_unchecked(&self.connection,rusqlite::TransactionBehavior::Immediate)?;
        self.resume_services(life,now)?;
        self.service_owner(actor,id,now/1000)?;
        let (record,approval) = self.group_service_facts(id,now)?;
        let view = self.current_service_group(&record,&approval)?;
        if request.group_id != view.group_id || request.expected_group_revision != view.revision
            || request.expected_service_revision != record.revision || request.aggregate_sha256 != service_edge_group_digest(&view)? { return Err(StorageError::Conflict); }
        let mut statement = tx.prepare("SELECT claims_json FROM service_publications WHERE service_id=?1 AND state=0 AND control_runtime_id=?2 ORDER BY node_id")?;
        let old: Vec<String> = statement.query_map(params![id,life.runtime_id],|r|r.get(0))?.collect::<Result<_,_>>()?;
        drop(statement);
        let mut members = Vec::new();
        if old.is_empty() {
            let draining: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM service_publications WHERE service_id=?1 AND state IN(0,1))",[id],|r|r.get(0))?;
            if draining { return Err(StorageError::RateLimited); }
            let total = view.members.iter().try_fold(0u64,|sum,member|bounded_add(sum,member.limits.maximum_bytes))?;
            if total > super::super::private::public_reservation_limit(&tx,&record)? { return Err(StorageError::RateLimited); }
            let mut generation: u64 = tx.query_row("SELECT COALESCE(max(generation),0) FROM service_publications WHERE service_id=?1",[id],|r|r.get(0))?;
            for member in &view.members {
                let edge = self.service_edge_live(&member.node_id,now)?;
                self.service_capacity_for_edge(&record,&edge,&member.node_id,&member.limits,now)?;
                generation = advance(generation)?;
                let publication_id = random_id();
                let usage = Self::reserve_service_usage_for_edge(&tx,signer,&record,&approval,&publication_id,generation,&edge.runtime,
                    edge.generation,member.namespace_revision,member.limits.maximum_bytes,now,&member.node_id,&member.limits)?;
                let usage_claims: ServiceUsageBudgetGrantClaims = decode_service_message(&usage.claims,SERVICE_USAGE_BYTES)?;
                if usage_claims.byte_ceiling != member.limits.maximum_bytes { return Err(StorageError::RateLimited); }
                let binding = ServiceEdgeGroupBinding {group:view.clone(),member_node_id:member.node_id.clone(),allocation:member.limits,aggregate_sha256:request.aggregate_sha256};
                let claims = self.make_service_claims(&record,&approval,&edge,PublicationVersion {id:publication_id,generation,sequence:1,usage_grant:usage,edge_group:Some(binding)},now)?;
                self.persist_group_publication(&tx,life,&record,&view,member,&claims,now)?;
                members.push(ServicePublicationIssue {claims,edge_public_key:edge.key});
            }
        } else {
            if old.len() != view.members.len() { return Err(StorageError::Conflict); }
            for (json,member) in old.into_iter().zip(&view.members) {
                let old: ServiceLeaseClaims = serde_json::from_str(&json)?;
                if old.expires_at_unix_ms <= now || old.edge_node_id() != member.node_id.as_str() { return Err(StorageError::Forbidden); }
                let (claims,key) = self.group_member_claims(&old,now,next(old.lease_sequence)?)?;
                self.persist_group_publication(&tx,life,&record,&view,member,&claims,now)?;
                members.push(ServicePublicationIssue {claims,edge_public_key:key});
            }
        }
        auditing::record(&tx,"service_edge_group_published",id,auditing::management(actor))?;
        tx.commit()?;
        Ok(ServiceGroupPublicationIssue {group:view,members})
    }
    #[allow(clippy::too_many_arguments)]
    fn persist_group_publication(&self, tx: &Transaction<'_>, life: &ServiceLifecycle, record: &Record, view: &ServiceEdgeGroupView, member: &ServiceEdgeGroupMember, claims: &ServiceLeaseClaims, now: u64) -> Result<(),StorageError> {
        let promised = bounded_add(claims.expires_at_unix_ms,HOLD_MARGIN_MS)?;
        self.reserve_group_namespace(tx,record,view,promised,now)?;
        let limits = member.limits;
        if tx.execute("INSERT INTO service_publications(id,service_id,account_id,node_id,service_revision,generation,control_runtime_id,ingress_key,namespace_revision,claims_json,promised_until,maximum_connections,bytes_per_second,maximum_bytes,edge_group_id,edge_group_revision) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16) ON CONFLICT(id) DO UPDATE SET claims_json=excluded.claims_json,promised_until=MAX(service_publications.promised_until,excluded.promised_until) WHERE service_publications.state=0 AND service_publications.control_runtime_id=excluded.control_runtime_id AND service_publications.edge_group_id=excluded.edge_group_id AND service_publications.edge_group_revision=excluded.edge_group_revision",
            params![claims.publication_id,record.id,record.account,member.node_id,record.revision,claims.publication_generation,life.runtime_id,member_ingress_key(record,&member.node_id),member.namespace_revision,serde_json::to_string(claims)?,promised,limits.maximum_connections,limits.bytes_per_second,limits.maximum_bytes,view.group_id,view.revision])? != 1 { return Err(StorageError::Conflict); }
        Ok(())
    }
    pub fn service_group_publication(&self, life: &ServiceLifecycle, actor: &Principal, id: &str, now: u64) -> Result<ServiceGroupPublicationIssue,StorageError> {
        let tx = self.connection.unchecked_transaction()?;
        self.resume_services(life,now)?;
        self.service_owner(actor,id,now/1000)?;
        let (record,approval) = self.group_service_facts(id,now)?;
        let view = self.current_service_group(&record,&approval)?;
        let mut members = Vec::new();
        for member in &view.members {
            let json: Option<String> = self.connection.query_row("SELECT claims_json FROM service_publications WHERE service_id=?1 AND node_id=?2 AND edge_group_id=?3 AND edge_group_revision=?4 AND state=0 AND control_runtime_id=?5",
                params![id,member.node_id,view.group_id,view.revision,life.runtime_id],|r|r.get(0)).optional()?;
            let claims: ServiceLeaseClaims = serde_json::from_str(&json.ok_or(StorageError::Forbidden)?)?;
            if claims.expires_at_unix_ms <= now { return Err(StorageError::Forbidden); }
            let (_,key) = self.group_member_claims(&claims,now,claims.lease_sequence)?;
            members.push(ServicePublicationIssue {claims,edge_public_key:key});
        }
        tx.commit()?;
        Ok(ServiceGroupPublicationIssue {group:view,members})
    }
    pub fn stop_service_group_publication(&mut self, actor: &Principal, id: &str, request: ServiceGroupPublicationRequest, now: u64) -> Result<(),StorageError> {
        request.validate()?;
        let tx = Transaction::new_unchecked(&self.connection,rusqlite::TransactionBehavior::Immediate)?;
        let record = self.service_owner(actor,id,now/1000)?;
        let (view,_) = configured(&tx,id)?.ok_or(StorageError::Forbidden)?;
        if record.revision != request.expected_service_revision || view.group_id != request.group_id
            || view.revision != request.expected_group_revision || service_edge_group_digest(&view)? != request.aggregate_sha256 { return Err(StorageError::Conflict); }
        tx.execute("UPDATE service_publications SET state=1 WHERE service_id=?1 AND edge_group_id=?2 AND state=0",params![id,view.group_id])?;
        auditing::record(&tx,"service_edge_group_stopped",id,auditing::management(actor))?;
        tx.commit()?;
        Ok(())
    }
    pub(super) fn hold_group_namespace(&self, tx: &Transaction<'_>, claims: &ServiceLeaseClaims, now: u64) -> Result<(),StorageError> {
        let binding = claims.edge_group.as_ref().ok_or(StorageError::Forbidden)?;
        let record = self.service_record(&claims.service_id)?;
        self.reserve_group_namespace(tx,&record,&binding.group,bounded_add(claims.expires_at_unix_ms,HOLD_MARGIN_MS)?,now)
    }
    pub(super) fn group_publication_status(&self, id: &str, now: u64) -> Result<Option<ServicePublicationStatus>,StorageError> {
        let mut statement = self.connection.prepare("SELECT p.state,p.claims_json,COALESCE(p.control_runtime_id=s.control_runtime_id AND s.restore_fenced=0,0),n.last_issued_at FROM service_publications p JOIN service_publication_settings s ON s.singleton=1 JOIN data_nodes n ON n.id=p.node_id WHERE p.service_id=?1 AND p.edge_group_id IS NOT NULL AND p.state IN(0,1) AND p.promised_until>?2 LIMIT 5")?;
        let rows = statement.query_map(params![id,now],|r|Ok((r.get::<_,u32>(0)?,r.get::<_,String>(1)?,r.get::<_,bool>(2)?,r.get::<_,u64>(3)?)))?;
        let mut any = false;
        for row in rows {
            any = true;
            let (state,json,runtime_current,node_issued) = row?;
            if state == 1 || !runtime_current { continue; }
            let claims: ServiceLeaseClaims = serde_json::from_str(&json)?;
            claims.validate()?;
            let at = now.max(claims.issued_at_unix_ms).max(node_issued);
            if at.saturating_sub(now)>=1000 || claims.expires_at_unix_ms<=at { continue; }
            match self.group_member_claims(&claims,at,claims.lease_sequence) {
                Ok(_) => return Ok(Some(ServicePublicationStatus::Published)),
                Err(StorageError::Forbidden|StorageError::Unauthorized|StorageError::Invalid(_)) => (),
                Err(error) => return Err(error),
            }
        }
        Ok(any.then_some(ServicePublicationStatus::Stopping))
    }
}
