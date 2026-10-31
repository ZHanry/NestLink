//! Real Store issuance, quota, persistence and signed node-resource delegation.
use super::*;
use nestlink_identity::{network::remote_route_set_reservation_transcript, nodes::NodeIdentity};
use nestlink_protocol::{NodeRole, NodeResourceQueryClaims, api::{NetworkRemoteRouteSetRequest, NetworkRemoteRouteSetMemberRequest, NodeEndpoints, NodeEndpointsUpdate, NodeRegistration, RelayQuotaUpdate}};
use nestlink_storage::relay_reservations::RelayLifecycle;

struct RouteSetFixture {
    base: Setup,
    lifecycle: RelayLifecycle,
    nodes: [(String, NodeIdentity, nestlink_protocol::NodeLeaseClaims); 2],
    clock: std::time::Instant,
}
impl RouteSetFixture {
    fn new(maximums: [u32; 2]) -> Result<Self> {
        let mut base = Setup::with_path(true, false)?;
        let mut nodes = Vec::new();
        for (index, maximum) in maximums.into_iter().enumerate() {
            let identity = NodeIdentity::generate();
            let id = random_id();
            base.store.register_node(&base.controller, NodeRegistration { id: id.clone(), name: format!("route-set-{index}"), public_key: URL_SAFE_NO_PAD.encode(identity.public_key()), roles: vec![NodeRole::NodeRelay as i32], max_connections: maximum, bytes_per_second: 100_000 })?;
            base.store.set_node_endpoints(&base.controller, &id, NodeEndpointsUpdate { expected_revision: 0, endpoints: NodeEndpoints { quic_uri: Some(format!("quic://127.0.0.1:{}", 32000 + index)), allow_loopback: true, ..NodeEndpoints::default() } }, NOW)?;
            let challenge = base.store.node_challenge(&id, NOW)?;
            let lease = base.store.issue_node_lease(&identity.prove(&challenge, &random_id())?, NOW)?;
            nodes.push((id, identity, lease));
        }
        let lifecycle = base.store.relay_lifecycle(NOW)?;
        Ok(Self { base, lifecycle, nodes: nodes.try_into().map_err(|_| "nodes")?, clock: std::time::Instant::now() })
    }
    fn request(&self) -> Result<NetworkRemoteRouteSetRequest> {
        let business = self.base.store.current_permit(&self.base.controller, &self.base.request, NOW / 1000)?;
        let mut ids = [random_id(), random_id()]; ids.sort();
        let mut request = NetworkRemoteRouteSetRequest { set_id: random_id(), path: self.base.issuance().request,
            members: [0,1].map(|index| NetworkRemoteRouteSetMemberRequest { allocation_id: ids[index].clone(), transit_grant_id: random_id(), node_id: self.nodes[index].0.clone() }),
            device_id: business.controller_device_id.clone(), signature: String::new() };
        self.sign(&mut request)?;
        Ok(request)
    }
    fn sign(&self, request: &mut NetworkRemoteRouteSetRequest) -> Result {
        let business = self.base.store.current_permit(&self.base.controller, &self.base.request, NOW / 1000)?;
        request.signature = URL_SAFE_NO_PAD.encode(self.base.controller_identity.sign_action(&remote_route_set_reservation_transcript(&business, &self.base.controller.account_id, &self.base.space, request)?)?);
        Ok(())
    }
    fn issue(&mut self, request: NetworkRemoteRouteSetRequest) -> std::result::Result<NetworkRemoteRouteSetBundle, StorageError> {
        self.base.store.issue_network_remote_route_set(&self.lifecycle, &self.base.controller, &self.base.signer, NetworkRemoteRouteSetIssuance { space_id: self.base.space.clone(), request_id: self.base.request.clone(), request }, NOW)
    }
    fn read(&mut self, set: &str) -> std::result::Result<NetworkRemoteRouteSetBundle, StorageError> {
        self.base.store.network_remote_route_set(&self.lifecycle, &self.base.host, &self.base.space, set, NOW)
    }
    fn held(&self) -> Result<u32> { Ok(self.base.store.relay_reservation_usage(&self.base.controller, NOW)?.held_allocations) }
    fn resource(&mut self, index: usize, sequence: u64) -> Result<nestlink_protocol::NodeResourceSnapshotClaims> {
        let now = NOW + u64::try_from(self.clock.elapsed().as_millis())?;
        let (id, identity, lease) = &self.nodes[index];
        let query = identity.sign_resource_query(&NodeResourceQueryClaims { schema_version: nestlink_protocol::SCHEMA_VERSION, deployment_id: lease.deployment_id.clone(), security_epoch: lease.security_epoch, node_id: id.clone(), runtime_id: lease.runtime_id.clone(), runtime_generation: lease.runtime_generation, policy_revision: lease.policy_revision, lease_sequence: lease.lease_sequence, request_id: random_id(), request_sequence: sequence, issued_at_unix_ms: now, expires_at_unix_ms: now+1000 })?;
        let root = PermitSigner::from_seed([44;32]);
        let claims = self.base.store.node_resource_snapshot_with_network(&self.lifecycle, &query, &root, now)?;
        let policy = root.node_policy_signer()?;
        let verified = nestlink_identity::node_resources::verify_resource_snapshot(&policy.sign_resource_snapshot(&claims)?, &policy.public_key(), &query)?;
        Ok(verified)
    }
}

#[test]
fn atomic_route_set_preserves_original_group_and_divides_one_cumulative_byte_budget() -> Result {
    let mut f = RouteSetFixture::new([2,2])?;
    let request = f.request()?;
    let set = request.set_id.clone();
    let path_id = request.path.path_grant_id.clone();
    let issued = f.issue(request.clone())?;
    assert_eq!(f.held()?, 2);
    let quota = f.base.store.relay_quota_current()?;
    let policy = &issued.path.verified().claims().policy;
    assert!(!policy.allow_direct); assert_eq!(policy.max_hops,1); assert_eq!(policy.relays.len(),2);
    let mut total = 0;
    for (index, member) in issued.members.iter().enumerate() {
        let GrantClaims::Transit(transit) = GrantClaims::decode_canonical(&member.transit.claims)? else { return Err("transit".into()); };
        assert_eq!(transit.transport_group, issued.path.verified().transport_group_id());
        assert_eq!(transit.route_id, request.members[index].allocation_id);
        assert_eq!((transit.previous,transit.next,transit.remaining_hops),(issued.path.verified().peers().first,issued.path.verified().peers().second,1));
        assert!(transit.byte_limit > 0); total += transit.byte_limit;
    }
    assert_eq!(total,quota.limits.bytes_per_allocation);
    assert!(matches!(f.issue(request),Err(StorageError::Conflict)));
    assert_eq!(f.held()?,2);
    let deployment = f.base.store.deployment_id()?;
    f.base.store = Store::from_snapshot(&f.base.store.snapshot()?, &deployment)?;
    let read = f.read(&set)?;
    assert_eq!(read.path.path.claims,issued.path.path.claims); assert_eq!(read.path.path.signature,issued.path.path.signature);
    for index in 0..2 { assert_eq!(read.members[index].transit.claims,issued.members[index].transit.claims); assert_eq!(read.members[index].transit.signature,issued.members[index].transit.signature); }
    assert!(f.base.store.network_remote_path(&f.base.host,&f.base.space,&path_id,NOW).is_err());
    for member in &issued.members { assert!(f.base.store.network_remote_relay(&f.lifecycle,&f.base.host,&f.base.space,&member.allocation_id,NOW).is_err()); }
    for _ in 0..2 { f.base.store.revoke_network_remote_route_set(&f.base.host,&f.base.space,&set,NOW)?; }
    assert!(f.read(&set).is_err()); assert_eq!(f.held()?,2);
    let snapshot = f.base.store.network_policy_snapshot(&f.base.space,NOW)?;
    assert!(issued.path.verified().check_current(&snapshot.verification()).is_err());
    for member in &issued.members { assert!(verify_network_grant(&member.transit,&snapshot.verification()).is_err()); }
    Ok(())
}

#[test]
fn second_member_node_global_and_account_capacity_failures_roll_back_the_entire_set() -> Result {
    for fault in 0..3 {
        let mut f = RouteSetFixture::new(if fault == 0 {[2,1]} else {[10,10]})?;
        if fault > 0 {
            let quota = f.base.store.relay_quota_current()?; let mut limits = quota.limits;
            if fault == 1 { limits.max_allocations = 1; } else { limits.max_account_endpoints = 1; }
            f.base.store.set_relay_quota(&f.base.controller,RelayQuotaUpdate {expected_revision:quota.revision,limits},NOW/1000)?;
        }
        let request = f.request()?; let set = request.set_id.clone();
        assert!(matches!(f.issue(request),Err(StorageError::RateLimited)),"fault {fault}");
        assert_eq!(f.held()?,0); assert!(f.read(&set).is_err());
        edit_snapshot(&mut f.base,|db| {
            for table in ["network_remote_paths","network_remote_route_sets","network_remote_route_set_members"] {
                assert_eq!(db.query_row(&format!("SELECT count(*) FROM {table}"),[],|row| row.get::<_,u64>(0))?,0);
            } Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn route_set_device_consent_covers_every_member_and_original_path_field() -> Result {
    let mut f = RouteSetFixture::new([10,10])?;
    for fault in 0..12 {
        let mut request = f.request()?;
        match fault {
            0 => request.set_id=random_id(), 1 => request.members[0].allocation_id=random_id(),
            2 => request.members[1].allocation_id=random_id(), 3 => request.members[0].transit_grant_id=random_id(),
            4 => request.members[1].transit_grant_id=random_id(), 5 => request.members.swap(0,1),
            6 => request.path.path_grant_id=random_id(), 7 => request.path.connectivity_grant_id=random_id(),
            8 => request.path.controller_membership_grant_id=random_id(), 9 => request.path.host_membership_grant_id=random_id(),
            10 => request.path.expires_at_unix_ms-=1, _ => request.path.expected_policy_epoch+=1,
        }
        assert!(f.issue(request).is_err(),"fault {fault}"); assert_eq!(f.held()?,0);
    }
    let mut request=f.request()?; request.members[1].node_id=request.members[0].node_id.clone(); assert!(f.sign(&mut request).is_err());
    Ok(())
}

#[test]
fn route_set_audit_failure_rolls_back_both_allocations_and_original_grants() -> Result {
    let mut f=RouteSetFixture::new([10,10])?;
    edit_snapshot(&mut f.base,|db| db.execute_batch("CREATE TRIGGER reject_route_set BEFORE INSERT ON audit WHEN NEW.event='network_remote_route_set_reserved' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;"))?;
    let request=f.request()?; assert!(matches!(f.issue(request),Err(StorageError::Sqlite(_)))); assert_eq!(f.held()?,0);
    Ok(())
}

#[test]
fn both_node_snapshots_delegate_only_their_original_member_and_withdraw_together() -> Result {
    let mut f=RouteSetFixture::new([2,2])?;
    let request=f.request()?; let set=request.set_id.clone(); let issued=f.issue(request)?;
    let root=PermitSigner::from_seed([44;32]);
    let mut bindings=Vec::new();
    for index in 0..2 {
        let snapshot=f.resource(index,1)?;
        assert!(snapshot.allocations.is_empty()); assert_eq!(snapshot.network_routes.len(),1);
        let resource=&snapshot.network_routes[0];
        let binding=nestlink_identity::network::verify_node_network_resource(resource,&root.public_key(),NOW)?;
        let allocation=resource.allocation.as_ref().ok_or("allocation")?;
        assert_eq!(allocation.allocation_id,issued.members[index].allocation_id);
        assert_eq!(binding.relay,nestlink_protocol::network::PeerId::from_public_key(&f.nodes[index].1.public_key()));
        assert_eq!(allocation.bytes_per_allocation,binding.byte_limit);
        let view:nestlink_protocol::api::NetworkRemoteRelayView=serde_json::from_slice(&resource.relay_bundle_json)?;
        assert_eq!(URL_SAFE_NO_PAD.decode(view.path.path.claims)?,issued.path.path.claims);
        assert_eq!(URL_SAFE_NO_PAD.decode(view.transit.claims)?,issued.members[index].transit.claims);
        let mut crossed=resource.clone(); crossed.allocation.as_mut().ok_or("allocation")?.allocation_id=issued.members[1-index].allocation_id.clone();
        assert!(nestlink_identity::network::verify_node_network_resource(&crossed,&root.public_key(),NOW).is_err());
        bindings.push(binding);
    }
    assert_ne!(bindings[0].digest,bindings[1].digest);
    let now=NOW+u64::try_from(f.clock.elapsed().as_millis())?;
    f.base.store.revoke_network_remote_route_set(&f.base.host,&f.base.space,&set,now)?;
    for index in 0..2 { assert!(f.resource(index,2)?.network_routes.is_empty()); }
    assert_eq!(f.held()?,2);
    Ok(())
}

#[test]
fn a_changed_node_endpoint_only_withdraws_that_original_candidate_without_refunding() -> Result {
    let mut f=RouteSetFixture::new([2,2])?;
    let request=f.request()?; let set=request.set_id.clone(); f.issue(request)?;
    f.base.store.set_node_endpoints(&f.base.controller,&f.nodes[0].0,NodeEndpointsUpdate {expected_revision:1,endpoints:NodeEndpoints {quic_uri:Some("quic://127.0.0.1:32999".into()),allow_loopback:true,..NodeEndpoints::default()}},NOW)?;
    let read=f.read(&set)?;
    assert!(!read.members[0].available); assert!(read.members[1].available);
    assert_eq!(read.members[0].node.revision,1);
    assert!(f.resource(0,1)?.network_routes.is_empty());
    assert_eq!(f.resource(1,1)?.network_routes.len(),1);
    assert_eq!(f.held()?,2);
    Ok(())
}

#[test]
fn revoking_one_node_preserves_the_other_original_grant_and_node_admission_resource() -> Result {
    let mut f=RouteSetFixture::new([2,2])?;
    let request=f.request()?; let set=request.set_id.clone(); let issued=f.issue(request)?;
    f.base.store.revoke_node(&f.base.controller,&f.nodes[0].0)?;
    let read=f.read(&set)?;
    assert!(!read.members[0].available); assert!(read.members[1].available);
    assert_eq!(read.path.path.claims,issued.path.path.claims);
    assert_eq!(read.path.path.signature,issued.path.path.signature);
    for index in 0..2 {
        assert_eq!(read.members[index].transit.claims,issued.members[index].transit.claims);
        assert_eq!(read.members[index].transit.signature,issued.members[index].transit.signature);
    }
    assert!(f.resource(0,1).is_err());
    let healthy=f.resource(1,1)?;
    assert_eq!(healthy.network_routes.len(),1);
    let root=PermitSigner::from_seed([44;32]);
    let binding=nestlink_identity::network::verify_node_network_resource(&healthy.network_routes[0],&root.public_key(),NOW)?;
    assert_eq!(binding.relay,nestlink_protocol::network::PeerId::from_public_key(&f.nodes[1].1.public_key()));
    let now=NOW+u64::try_from(f.clock.elapsed().as_millis())?;
    f.base.store.revoke_network_remote_route_set(&f.base.host,&f.base.space,&set,now)?;
    assert!(f.resource(1,2)?.network_routes.is_empty()); assert_eq!(f.held()?,2);
    Ok(())
}
