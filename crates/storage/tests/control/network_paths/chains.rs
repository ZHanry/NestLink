use super::*;
use nestlink_identity::{
    network::remote_chain_reservation_transcript,
    network_topology::{verify_topology_advertisement,verify_topology_publisher},
    nodes::NodeIdentity,
};
use nestlink_protocol::{
    NodeRole,
    api::{NetworkRemoteRelayChainRequest,NodeRegistration,NodeEndpoints,NodeEndpointsUpdate,RelayQuotaUpdate},
    network::PeerId,
    network_topology::{BootIncarnation,TopologyNeighbor,TopologyReport},
};
use nestlink_storage::{network_policy::topology::TopologyPublisherRequest,relay_reservations::RelayLifecycle};

struct ChainFixture {
    base: Setup,
    lifecycle: RelayLifecycle,
    nodes: [(String,NodeIdentity,BootIncarnation);2],
    digests: [[u8;32];2],
}
impl ChainFixture {
    fn new(maximums:[u32;2]) -> Result<Self> {
        let mut base = Setup::with_path(true,false)?;
        let mut registered = Vec::new();
        for (index,maximum) in maximums.into_iter().enumerate() {
            let identity = NodeIdentity::generate();
            let id = random_id();
            base.store.register_node(&base.controller,NodeRegistration {
                id:id.clone(),name:format!("chain-{index}"),public_key:URL_SAFE_NO_PAD.encode(identity.public_key()),
                roles:vec![NodeRole::NodeRelay as i32],max_connections:maximum,bytes_per_second:100_000,
            })?;
            base.store.set_node_endpoints(&base.controller,&id,NodeEndpointsUpdate {
                expected_revision:0,endpoints:NodeEndpoints {
                    quic_uri:Some(format!("quic://127.0.0.1:{}",31000+index)),allow_loopback:true,..NodeEndpoints::default()
                },
            },NOW)?;
            let runtime = random_id();
            let challenge = base.store.node_challenge(&id,NOW)?;
            let lease = base.store.issue_node_lease(&identity.prove(&challenge,&runtime)?,NOW)?;
            registered.push((id,identity,BootIncarnation {runtime_id:runtime,runtime_generation:lease.runtime_generation}));
        }
        let nodes:[_;2] = registered.try_into().map_err(|_|"nodes")?;
        let mut publishers = Vec::new();
        for index in 0..2 {
            publishers.push(base.store.issue_topology_publisher(&base.controller,&base.signer,&base.space,&nodes[index].0,TopologyPublisherRequest {
                publisher_id:random_id(),expected_policy_epoch:3,allowed_node_ids:vec![nodes[1-index].0.clone()],expires_at_ms:NOW+60_000,
            },NOW)?);
        }
        let mut digests = Vec::new();
        for index in 0..2 {
            let snapshot = base.store.network_policy_snapshot(&base.space,NOW)?;
            let (id,identity,incarnation) = &nodes[index];
            let publisher = verify_topology_publisher(&publishers[index],&snapshot.verification(),id,&identity.public_key(),incarnation,&[])?;
            let report = identity.sign_topology_report(&TopologyReport {
                schema_version:1,deployment_id:base.store.deployment_id()?,space_id:base.space.clone(),policy_epoch:3,
                node_id:id.clone(),peer:PeerId::from_public_key(&identity.public_key()),publisher_digest:publisher.digest(),
                incarnation:incarnation.clone(),sequence:1,not_before_ms:NOW,expires_at_ms:NOW+5000,
                neighbors:vec![TopologyNeighbor {
                    local:PeerId::from_public_key(&identity.public_key()),remote:PeerId::from_public_key(&nodes[1-index].1.public_key()),
                    local_endpoint_revision:1,remote_endpoint_revision:1,up:true,
                }],prefixes:Vec::new(),
            })?;
            let signed = base.store.accept_topology_report(&base.signer,&base.space,id,&report,NOW)?;
            let verified = verify_topology_advertisement(&signed,&publisher,&snapshot.verification(),incarnation,0)?;
            digests.push(verified.digest());
        }
        let lifecycle = base.store.relay_lifecycle(NOW)?;
        Ok(Self { base,lifecycle,nodes,digests:digests.try_into().map_err(|_|"digests")? })
    }
    fn request(&self) -> Result<NetworkRemoteRelayChainRequest> {
        let business = self.base.store.current_permit(&self.base.controller,&self.base.request,NOW/1000)?;
        let mut request = NetworkRemoteRelayChainRequest {
            route_id:random_id(),path:self.base.issuance().request,
            node_ids:self.nodes.each_ref().map(|node|node.0.clone()),transit_grant_ids:[random_id(),random_id()],
            topology_digests:self.digests,device_id:business.controller_device_id.clone(),signature:String::new(),
        };
        self.sign(&mut request)?;
        Ok(request)
    }
    fn sign(&self,request:&mut NetworkRemoteRelayChainRequest) -> Result {
        let business = self.base.store.current_permit(&self.base.controller,&self.base.request,NOW/1000)?;
        let transcript = remote_chain_reservation_transcript(&business,&self.base.controller.account_id,&self.base.space,request)?;
        request.signature = URL_SAFE_NO_PAD.encode(self.base.controller_identity.sign_action(&transcript)?);
        Ok(())
    }
    fn issue(&mut self,request:NetworkRemoteRelayChainRequest) -> std::result::Result<NetworkRemoteRelayChainBundle,StorageError> {
        self.base.store.issue_network_remote_chain(&self.lifecycle,&self.base.controller,&self.base.signer,NetworkRemoteRelayChainIssuance {
            space_id:self.base.space.clone(),request_id:self.base.request.clone(),request,
        },NOW)
    }
    fn held(&self) -> Result<u32> {
        Ok(self.base.store.relay_reservation_usage(&self.base.controller,NOW)?.held_allocations)
    }
    fn read(&mut self,route:&str) -> std::result::Result<NetworkRemoteRelayChainBundle,StorageError> {
        self.base.store.network_remote_chain(&self.lifecycle,&self.base.host,&self.base.space,route,NOW)
    }
}

#[test]
fn atomic_chain_persists_exact_ordered_transits_and_revokes_without_refunding() -> Result {
    let mut f = ChainFixture::new([2,2])?;
    let request = f.request()?;
    let route = request.route_id.clone();
    let issued = f.issue(request.clone())?;
    assert_eq!(f.held()?,2);
    let claims = issued.transits.each_ref().map(|signed|GrantClaims::decode_canonical(&signed.claims));
    let [first,second] = claims;
    let (GrantClaims::Transit(a),GrantClaims::Transit(b)) = (first?,second?) else { return Err("transit".into()); };
    let peers = issued.path.verified().peers();
    assert_eq!([a.relay,b.relay],f.nodes.each_ref().map(|node|PeerId::from_public_key(&node.1.public_key())));
    assert_eq!((a.previous,a.next,a.remaining_hops),(peers.first,b.relay,2));
    assert_eq!((b.previous,b.next,b.remaining_hops),(a.relay,peers.second,1));
    assert_eq!((&a.route_id,&b.route_id),(&route,&route));
    assert_eq!(a.transport_group,b.transport_group);
    assert!(matches!(f.issue(request),Err(StorageError::Conflict)));
    let deployment = f.base.store.deployment_id()?;
    f.base.store = Store::from_snapshot(&f.base.store.snapshot()?,&deployment)?;
    let read = f.read(&route)?;
    for index in 0..2 {
        assert_eq!(read.transits[index].claims,issued.transits[index].claims);
        assert_eq!(read.transits[index].signature,issued.transits[index].signature);
    }
    assert_eq!(read.path.path.claims,issued.path.path.claims);
    assert!(f.base.store.network_remote_relay(&f.lifecycle,&f.base.host,&f.base.space,&route,NOW).is_err());
    for _ in 0..2 { f.base.store.revoke_network_remote_chain(&f.base.host,&f.base.space,&route,NOW)?; }
    assert!(f.read(&route).is_err());
    assert_eq!(f.held()?,2);
    let snapshot = f.base.store.network_policy_snapshot(&f.base.space,NOW)?;
    for signed in &issued.transits { assert!(verify_network_grant(signed,&snapshot.verification()).is_err()); }
    assert!(issued.path.verified().check_current(&snapshot.verification()).is_err());
    Ok(())
}

#[test]
fn second_hop_capacity_failure_rolls_back_both_promises_and_all_credentials() -> Result {
    let mut f = ChainFixture::new([2,1])?;
    let request = f.request()?;
    let route = request.route_id.clone();
    assert!(matches!(f.issue(request),Err(StorageError::RateLimited)));
    assert_eq!(f.held()?,0);
    assert!(f.read(&route).is_err());
    edit_snapshot(&mut f.base,|db| {
        for table in ["network_remote_paths","network_remote_chains","network_remote_chain_hops"] {
            assert_eq!(db.query_row(&format!("SELECT count(*) FROM {table}"),[],|r|r.get::<_,u64>(0))?,0);
        }
        Ok(())
    })?;
    Ok(())
}

#[test]
fn global_quota_counts_both_hops_and_audit_failure_rolls_back_everything() -> Result {
    let mut f = ChainFixture::new([10,10])?;
    let quota = f.base.store.relay_quota_current()?;
    let mut limits = quota.limits;
    limits.max_allocations = 1;
    let quota = f.base.store.set_relay_quota(&f.base.controller,RelayQuotaUpdate {expected_revision:quota.revision,limits},NOW/1000)?;
    let request = f.request()?;
    assert!(matches!(f.issue(request),Err(StorageError::RateLimited)));
    assert_eq!(f.held()?,0);
    let mut limits = quota.limits;
    limits.max_allocations = 2;
    f.base.store.set_relay_quota(&f.base.controller,RelayQuotaUpdate {expected_revision:quota.revision,limits},NOW/1000)?;
    edit_snapshot(&mut f.base,|db|db.execute_batch("CREATE TRIGGER reject_chain BEFORE INSERT ON audit WHEN NEW.event='network_remote_chain_reserved' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;"))?;
    let request = f.request()?;
    assert!(matches!(f.issue(request),Err(StorageError::Sqlite(_))));
    assert_eq!(f.held()?,0);
    Ok(())
}

#[test]
fn both_account_endpoint_promises_share_the_existing_limit() -> Result {
    let mut f = ChainFixture::new([10,10])?;
    let quota = f.base.store.relay_quota_current()?;
    let mut limits = quota.limits;
    limits.max_account_endpoints = 1;
    f.base.store.set_relay_quota(&f.base.controller,RelayQuotaUpdate {expected_revision:quota.revision,limits},NOW/1000)?;
    let request = f.request()?;
    assert!(matches!(f.issue(request),Err(StorageError::RateLimited)));
    assert_eq!(f.held()?,0);
    Ok(())
}

#[test]
fn device_proof_binds_order_both_topology_references_and_all_grant_identifiers() -> Result {
    let mut f = ChainFixture::new([10,10])?;
    for fault in 0..10 {
        let mut request = f.request()?;
        match fault {
            0=>request.node_ids.swap(0,1),
            1=>request.topology_digests[0][0]^=1,
            2=>request.topology_digests[1][0]^=1,
            3=>request.transit_grant_ids[0]=random_id(),
            4=>request.transit_grant_ids[1]=random_id(),
            5=>request.path.path_grant_id=random_id(),
            6=>request.path.connectivity_grant_id=random_id(),
            7=>request.route_id=random_id(),
            8=>request.path.expires_at_unix_ms-=1,
            _=>request.path.controller_membership_grant_id=random_id(),
        }
        assert!(f.issue(request).is_err(),"accepted changed field {fault}");
        assert_eq!(f.held()?,0);
    }
    let mut request = f.request()?;
    request.node_ids[1]=request.node_ids[0].clone();
    assert!(f.sign(&mut request).is_err());
    let mut request = f.request()?;
    request.topology_digests[1][0]^=1;
    f.sign(&mut request)?;
    assert!(f.issue(request).is_err());
    assert_eq!(f.held()?,0);
    Ok(())
}

#[test]
fn simultaneous_chain_transactions_cannot_split_or_overbook_two_remaining_slots() -> Result {
    use std::sync::{Arc,Barrier};
    let f = ChainFixture::new([10,10])?;
    let requests = [f.request()?,f.request()?];
    let ChainFixture {mut base,lifecycle,..} = f;
    let quota = base.store.relay_quota_current()?;
    let mut limits = quota.limits;
    limits.max_allocations = 2;
    base.store.set_relay_quota(&base.controller,RelayQuotaUpdate {expected_revision:quota.revision,limits},NOW/1000)?;
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("chain-concurrency.sqlite3");
    let deployment = base.store.deployment_id()?;
    std::fs::write(&database,base.store.snapshot()?)?;
    let lifecycle = Arc::new(lifecycle);
    let barrier = Arc::new(Barrier::new(2));
    let stores = [Store::open_existing(&database,&deployment)?,Store::open_existing(&database,&deployment)?];
    let workers = stores.into_iter().zip(requests).map(|(mut store,request)| {
        let (actor,lifecycle,barrier) = (base.controller.clone(),lifecycle.clone(),barrier.clone());
        let issuance = NetworkRemoteRelayChainIssuance {space_id:base.space.clone(),request_id:base.request.clone(),request};
        std::thread::spawn(move || -> std::result::Result<bool,StorageError> {
            barrier.wait();
            let signer = NetworkAuthoritySigner::from_master_seed(&[63;32])?;
            match store.issue_network_remote_chain(&lifecycle,&actor,&signer,issuance,NOW) {
                Ok(_)=>Ok(true),Err(StorageError::RateLimited)=>Ok(false),Err(error)=>Err(error),
            }
        })
    }).collect::<Vec<_>>();
    let mut admitted = 0;
    for worker in workers { admitted += usize::from(worker.join().map_err(|_|"chain worker panicked")??); }
    assert_eq!(admitted,1);
    let store = Store::open_existing(&database,&deployment)?;
    assert_eq!(store.relay_reservation_usage(&base.controller,NOW)?.held_allocations,2);
    let db = rusqlite::Connection::open(&database)?;
    assert_eq!(db.query_row("SELECT count(*) FROM network_remote_chains",[],|r|r.get::<_,u64>(0))?,1);
    assert_eq!(db.query_row("SELECT count(*) FROM network_remote_chain_hops",[],|r|r.get::<_,u64>(0))?,2);
    assert_eq!(db.query_row("SELECT count(*) FROM network_remote_paths",[],|r|r.get::<_,u64>(0))?,1);
    Ok(())
}

#[test]
fn business_revocation_or_originating_login_logout_ends_the_whole_chain() -> Result {
    for logout in [false,true] {
        let mut f = ChainFixture::new([2,2])?;
        let request = f.request()?;
        let route = request.route_id.clone();
        f.issue(request)?;
        if logout { f.base.store.logout(&f.base.controller)?; }
        else { f.base.store.revoke_remote(&f.base.host,&f.base.request)?; }
        assert!(f.read(&route).is_err());
        assert_eq!(f.held()?,2);
    }
    Ok(())
}

#[test]
fn topology_publisher_revoke_or_endpoint_change_invalidates_entire_reserved_chain() -> Result {
    for change_endpoint in [false,true] {
        let mut f = ChainFixture::new([2,2])?;
        let request = f.request()?;
        let route = request.route_id.clone();
        f.issue(request)?;
        if change_endpoint {
            f.base.store.set_node_endpoints(&f.base.controller,&f.nodes[1].0,NodeEndpointsUpdate {
                expected_revision:1,endpoints:NodeEndpoints {quic_uri:Some("quic://127.0.0.1:32001".into()),allow_loopback:true,..NodeEndpoints::default()},
            },NOW)?;
        } else {
            f.base.store.revoke_topology_publisher(&f.base.controller,&f.base.space,&f.nodes[1].0,NOW)?;
        }
        assert!(f.read(&route).is_err());
        assert_eq!(f.held()?,2);
    }
    Ok(())
}
