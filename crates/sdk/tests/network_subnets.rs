//! Real SDK/HTTP/SQLite and independent signatures. This qualifies mapping
//! control authority; it does not claim OS forwarding or overlapping-site I/O.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, hash_password, random_id};
use nestlink_identity::{PermitSigner, network::{NetworkVerification, verify_network_grant}, nodes::NodeIdentity, subnet::{SubnetGatewayState, verify_subnet_mapping}};
use nestlink_protocol::{NodeRole, api::{NodeEndpoints, NodeEndpointsUpdate, NodeRegistration, NetworkRouteExportRequest}, network::{IpPrefix, SpaceRole}, network_topology::BootIncarnation,
    spaces::{SpaceCreateRequest, SpaceInvitationRequest, SpaceInvitationAcceptance}, subnet::{SubnetMappingClaims, management::*}};
use nestlink_sdk::{DeploymentTrust, Sdk, SdkError, network_management::decode_network_grant};
use nestlink_server::{AppState, router};
use nestlink_storage::{Store, StorageError};
use std::{collections::BTreeSet, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PASSWORD: &str = "subnet-mapping-management-test-password";
fn now() -> Result<u64> { Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().try_into()?) }
fn status<T>(result: std::result::Result<T,SdkError>, expected: u16) {
    assert!(matches!(result, Err(SdkError::Api(code,_)) if code.as_u16()==expected));
}
async fn login(origin: &str, deployment: &str, issuer: [u8;32], name: &str) -> Result<Sdk> {
    let mut sdk = Sdk::connect(origin, DeploymentTrust { deployment_id: deployment.into(), permit_issuer: issuer }, true).await?;
    sdk.login(name.into(), Secret::from_text(PASSWORD.into()), None).await?;
    Ok(sdk)
}
struct Server(Option<tokio::task::JoinHandle<std::io::Result<()>>>);
impl Drop for Server { fn drop(&mut self) { if let Some(task)=&self.0 { task.abort(); } } }
struct Node { id: String, identity: NodeIdentity, incarnation: BootIncarnation }
struct Fixture {
    server: Server, directory: tempfile::TempDir, database: PathBuf, deployment: String,
    manager: Sdk, member: Sdk, stranger: Sdk, space: String, authority: [u8;32], nodes: Vec<Node>,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let directory=tempfile::tempdir()?;
        let database=directory.path().join("network-subnets.sqlite3");
        let deployment=random_id();
        let signer=PermitSigner::generate();
        let issuer=signer.public_key();
        let authority=signer.network_authority_signer()?.public_key();
        let vault=VaultKey::from_bytes([76;32]);
        let mut store=Store::open(&database,&deployment)?;
        store.bootstrap_admin("manager",PASSWORD)?;
        let dummy=hash_password("subnet-login-unused-dummy")?;
        let actor=store.login("manager",PASSWORD,None,now()?/1000,&vault,&dummy)?.principal;
        let mut pending_nodes=Vec::new();
        for index in 0..2 {
            let identity=NodeIdentity::generate();
            let id=random_id();
            store.register_node(&actor,NodeRegistration {id:id.clone(),name:format!("subnet gateway {index}"),public_key:URL_SAFE_NO_PAD.encode(identity.public_key()),roles:vec![NodeRole::NodeRelay as i32],max_connections:16,bytes_per_second:1_048_576})?;
            store.set_node_endpoints(&actor,&id,NodeEndpointsUpdate {expected_revision:0,endpoints:NodeEndpoints {quic_uri:Some(format!("quic://127.0.0.1:{}",31960+index)),allow_loopback:true,..NodeEndpoints::default()}},now()?)?;
            pending_nodes.push((id,identity));
        }
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin=format!("http://{}",listener.local_addr()?);
        let app=router(AppState::new(store,vault,signer,origin.clone(),false)?);
        let server=Server(Some(tokio::spawn(async move {axum::serve(listener,app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await})));
        let manager=login(&origin,&deployment,issuer,"manager").await?;
        for name in ["member","stranger"] {manager.create_account(name.into(),Secret::from_text(PASSWORD.into())).await?;}
        let member=login(&origin,&deployment,issuer,"member").await?;
        let stranger=login(&origin,&deployment,issuer,"stranger").await?;
        let space=manager.create_space(SpaceCreateRequest{name:"exact subnet aliases".into()}).await?.space_id;
        let detail=manager.space_details(&space).await?.space;
        let invitation=manager.invite_to_space(&space,SpaceInvitationRequest {expected_revision:detail.revision,role:SpaceRole::Member,
            target_account_id:Some(member.principal().ok_or("member principal missing")?.account_id.clone()),expires_at_unix_ms:now()?+60_000}).await?;
        member.accept_space_invitation(&space,&invitation.invitation.invitation_id,SpaceInvitationAcceptance{token:invitation.token}).await?;
        // Register the first accepted boot after password and space setup, so
        // setup cannot consume the short production node lease. Never renew a
        // signed mapping, alter production deadlines or resurrect an old boot.
        let mut reopened=Store::open_existing(&database,&deployment)?;
        let mut nodes=Vec::new();
        for (id,identity) in pending_nodes {
            let runtime_id=random_id();
            let challenge=reopened.node_challenge(&id,now()?)?;
            let lease=reopened.issue_node_lease(&identity.prove(&challenge,&runtime_id)?,now()?)?;
            nodes.push(Node{id,identity,incarnation:BootIncarnation{runtime_id,runtime_generation:lease.runtime_generation}});
        }
        drop(reopened);
        Ok(Self{server,directory,database,deployment,manager,member,stranger,space,authority,nodes})
    }
    async fn request(&self,node:usize,alias:&str) -> Result<SubnetMappingRequest> {
        let original=IpPrefix{network:"192.168.1.0".parse()?,prefix_len:24};
        let alias=IpPrefix{network:alias.parse()?,prefix_len:24};
        let policy=self.manager.network_policy(&self.space).await?;
        let export=self.manager.issue_network_route_export(&self.space,&self.nodes[node].id,NetworkRouteExportRequest {
            grant_id:random_id(),expected_revision:policy.revision,expected_policy_epoch:policy.policy_epoch,prefixes:vec![original,alias],expires_at_ms:now()?+60_000 }).await?;
        let policy=self.manager.network_policy(&self.space).await?;
        Ok(SubnetMappingRequest{mapping_version:1,grant_id:random_id(),gateway_node_id:self.nodes[node].id.clone(),route_export_grant_id:export.grant_id,
            expected_revision:policy.revision,expected_policy_epoch:policy.policy_epoch,expected_gateway_incarnation:self.nodes[node].incarnation.clone(),
            original,alias,expires_at_ms:now()?+60_000})
    }
    fn verify(&self,view:&SubnetMappingView) -> Result<SubnetMappingClaims> {
        assert_eq!(view.policy.authority_public_key,URL_SAFE_NO_PAD.encode(self.authority),"verify against the independently provisioned authority, not a response-selected key");
        let revoked=BTreeSet::new();
        let context=NetworkVerification {authority_key:&self.authority,deployment_id:&self.deployment,space_id:&self.space,policy_epoch:view.policy.policy_epoch,
            now_ms:now()?,revoked_grant_ids:&revoked};
        let export=verify_network_grant(&decode_network_grant(&view.route_export)?,&context)?;
        let gateway=SubnetGatewayState{node_id:&view.gateway.node_id,public_key:&view.gateway.public_key,incarnation:&view.gateway.incarnation,
            mapping_revision:view.gateway.mapping_revision,lease_expires_at_ms:view.gateway.lease_expires_at_ms};
        let mapping=verify_subnet_mapping(&view.mapping,&context,export,&gateway)?;
        Ok(mapping.claims().clone())
    }
    async fn finish(mut self) -> Result {
        if let Some(task)=self.server.0.take() {task.abort(); let _=task.await;}
        self.directory.close()?;
        Ok(())
    }
}

#[tokio::test]
async fn two_originally_overlapping_sites_keep_exact_signed_bytes_and_permissions_across_reopen() -> Result {
    let f=Fixture::new().await?;
    let request=f.request(0,"10.210.1.0").await?;
    status(f.member.issue_subnet_mapping(&f.space,&request).await,403);
    status(f.stranger.issue_subnet_mapping(&f.space,&request).await,403);
    let first=f.manager.issue_subnet_mapping(&f.space,&request).await?;
    let claims=f.verify(&first)?;
    assert_eq!(claims.original,request.original);
    assert_eq!(claims.alias,request.alias);
    assert_eq!(claims.mapping_revision,1);
    assert!(claims.scope.expires_at_ms<=first.gateway.lease_expires_at_ms);
    let second_request=f.request(1,"10.210.2.0").await?;
    let second=f.manager.issue_subnet_mapping(&f.space,&second_request).await?;
    assert_eq!(f.verify(&second)?.original,claims.original);
    assert_ne!(f.verify(&second)?.alias,claims.alias);
    let read=f.manager.subnet_mapping(&f.space,&request.grant_id).await?;
    assert_eq!(read.mapping,first.mapping);
    status(f.stranger.subnet_mapping(&f.space,&request.grant_id).await,403);
    assert_eq!(f.member.subnet_mapping(&f.space,&request.grant_id).await?.mapping,first.mapping);
    status(f.manager.issue_subnet_mapping(&f.space,&request).await,409);
    let mut reopened=Store::open_existing(&f.database,&f.deployment)?;
    let actor=f.manager.principal().ok_or("manager missing")?;
    let recovered=reopened.subnet_mapping(actor,&f.space,&request.grant_id,now()?)?;
    assert_eq!(recovered.mapping,first.mapping);
    drop(reopened);
    f.finish().await
}

#[tokio::test]
async fn real_concurrent_alias_claims_and_same_gateway_original_conflicts_roll_back() -> Result {
    let f=Fixture::new().await?;
    let mut a=f.request(0,"10.210.1.0").await?;
    let mut b=f.request(1,"10.210.1.0").await?;
    let revision=f.manager.network_policy(&f.space).await?.revision;
    a.expected_revision=revision; b.expected_revision=revision;
    let (left,right)=tokio::join!(f.manager.issue_subnet_mapping(&f.space,&a),f.manager.issue_subnet_mapping(&f.space,&b));
    let (winner,mut loser,winning_node)=match (left,right) {
        (Ok(view),Err(SdkError::Api(code,_))) if code.as_u16()==409=>(view,b,0),
        (Err(SdkError::Api(code,_)),Ok(view)) if code.as_u16()==409=>(view,a,1),
        _=>return Err("concurrent alias requests must commit exactly one mapping".into()),
    };
    loser.expected_revision=f.manager.network_policy(&f.space).await?.revision;
    status(f.manager.issue_subnet_mapping(&f.space,&loser).await,409);
    status(f.manager.subnet_mapping(&f.space,&loser.grant_id).await,403);
    let same_gateway=f.request(winning_node,"10.210.3.0").await?;
    status(f.manager.issue_subnet_mapping(&f.space,&same_gateway).await,409);
    let winner_claims=f.verify(&winner)?;
    assert_eq!(f.manager.subnet_mapping(&f.space,&winner_claims.scope.grant_id).await?.mapping,winner.mapping);
    f.finish().await
}

#[tokio::test]
async fn revoke_retains_namespace_and_tombstones_and_does_not_reissue_on_retry() -> Result {
    let f=Fixture::new().await?;
    let request=f.request(0,"10.210.1.0").await?;
    let first=f.manager.issue_subnet_mapping(&f.space,&request).await?;
    let revision=f.manager.network_policy(&f.space).await?.revision;
    let revoke=SubnetMappingRevoke{expected_revision:revision,expected_mapping_revision:1};
    status(f.member.revoke_subnet_mapping(&f.space,&request.grant_id,&revoke).await,403);
    let mut wrong=revoke.clone(); wrong.expected_mapping_revision=2;
    status(f.manager.revoke_subnet_mapping(&f.space,&request.grant_id,&wrong).await,409);
    let revoked=f.manager.revoke_subnet_mapping(&f.space,&request.grant_id,&revoke).await?;
    let again=f.manager.revoke_subnet_mapping(&f.space,&request.grant_id,&SubnetMappingRevoke{expected_revision:revoked.revision,expected_mapping_revision:1}).await?;
    assert_eq!(again.revision,revoked.revision);
    status(f.manager.subnet_mapping(&f.space,&request.grant_id).await,403);
    let mut retry=request.clone(); retry.expected_revision=again.revision;
    status(f.manager.issue_subnet_mapping(&f.space,&retry).await,409);
    let replacement=f.request(1,"10.210.1.0").await?;
    status(f.manager.issue_subnet_mapping(&f.space,&replacement).await,409);
    let mut reopened=Store::open_existing(&f.database,&f.deployment)?;
    let snapshot=reopened.network_policy_snapshot(&f.space,now()?)?;
    assert!(snapshot.verification().revoked_grant_ids.contains(&request.grant_id));
    let held=SubnetMappingClaims::decode_canonical(&first.mapping.claims)?;
    assert_eq!(held.mapping_revision,1,"original signed bytes are never rewritten to the tombstone revision");
    assert!(matches!(reopened.subnet_mapping(f.manager.principal().ok_or("manager missing")?,&f.space,&request.grant_id,now()?),Err(StorageError::Forbidden)));
    drop(reopened);
    f.finish().await
}

#[tokio::test]
async fn registered_gateway_restart_stops_its_mapping_and_export_revoke_stops_the_sibling() -> Result {
    let f=Fixture::new().await?;
    let first_request=f.request(0,"10.210.1.0").await?;
    let first=f.manager.issue_subnet_mapping(&f.space,&first_request).await?;
    let second_request=f.request(1,"10.210.2.0").await?;
    let second=f.manager.issue_subnet_mapping(&f.space,&second_request).await?;
    let mut reopened=Store::open_existing(&f.database,&f.deployment)?;
    let challenge=reopened.node_challenge(&f.nodes[0].id,now()?)?;
    let next=reopened.issue_node_lease(&f.nodes[0].identity.prove(&challenge,&random_id())?,now()?)?;
    assert!(next.runtime_generation>f.nodes[0].incarnation.runtime_generation);
    let snapshot=reopened.network_policy_snapshot(&f.space,now()?)?;
    assert!(snapshot.verification().revoked_grant_ids.contains(&first_request.grant_id));
    drop(reopened);
    status(f.manager.subnet_mapping(&f.space,&first_request.grant_id).await,403);
    assert_eq!(f.manager.subnet_mapping(&f.space,&second_request.grant_id).await?.mapping,second.mapping);
    let revision=f.manager.network_policy(&f.space).await?.revision;
    f.manager.revoke_network_route_export(&f.space,&second.route_export.grant_id,revision).await?;
    status(f.manager.subnet_mapping(&f.space,&second_request.grant_id).await,403);
    let mut reopened=Store::open_existing(&f.database,&f.deployment)?;
    let snapshot=reopened.network_policy_snapshot(&f.space,now()?)?;
    assert!(snapshot.verification().revoked_grant_ids.contains(&second_request.grant_id));
    let authority:[u8;32]=URL_SAFE_NO_PAD.decode(&first.policy.authority_public_key)?.try_into().map_err(|_|"authority key length")?;
    assert!(verify_network_grant(&decode_network_grant(&first.route_export)?,&snapshot.verification()).is_ok(),"route publication is not the old runtime-bound mapping");
    assert_eq!(authority,*snapshot.verification().authority_key);
    drop(reopened);
    f.finish().await
}

#[tokio::test]
async fn exact_export_gateway_epoch_deadline_and_route_family_cannot_be_substituted() -> Result {
    let f=Fixture::new().await?;
    let original=f.request(0,"10.210.1.0").await?;
    for fault in 0..5 {
        let mut request=original.clone();
        match fault {
            0=>request.expected_gateway_incarnation.runtime_generation+=1,
            1=>request.expected_policy_epoch+=1,
            2=>request.gateway_node_id=f.nodes[1].id.clone(),
            3=>request.alias.network="10.211.1.0".parse()?,
            4=>request.original=IpPrefix{network:"0.0.0.0".parse()?,prefix_len:0},
            _=>unreachable!(),
        }
        let result=f.manager.issue_subnet_mapping(&f.space,&request).await;
        assert!(matches!(result,Err(SdkError::Api(code,_)) if matches!(code.as_u16(),400|403|409)),"substitution fault {fault}");
    }
    let view=f.manager.issue_subnet_mapping(&f.space,&original).await?;
    let claims=f.verify(&view)?;
    let mut reopened=Store::open_existing(&f.database,&f.deployment)?;
    assert!(reopened.subnet_mapping(f.manager.principal().ok_or("manager missing")?,&f.space,&original.grant_id,claims.scope.expires_at_ms).is_err());
    assert!(matches!(reopened.subnet_mapping(f.manager.principal().ok_or("manager missing")?,&f.space,&original.grant_id,now()?),Err(StorageError::Conflict)),"a later clock rollback cannot revive an observed-expired mapping");
    drop(reopened);
    f.finish().await
}
