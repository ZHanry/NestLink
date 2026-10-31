//! Actual management HTTP and independently signed node poll/report requests
//! against file SQLite. This proves control-plane accounting, not edge HA.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, hash_password, random_id};
use nestlink_identity::{PermitSigner, digest, nodes::{NodeIdentity,verify_service_usage_ack},
    service_plane::{verify_service_lease,verify_service_snapshot,verify_service_usage_budget_grant,group::service_edge_group_digest}};
use nestlink_policy::{NetworkPolicy, PeerPathMode, PublicIngress, ServerForwarding};
use nestlink_protocol::{NodeRole, NodeLeaseClaims, NodeResourceQueryClaims, SCHEMA_VERSION, NODE_RESOURCE_TTL_MS,
    api::*,service_plane::{*,group::*,publication::*}};
use nestlink_sdk::{DeploymentTrust,DeviceIdentity,Sdk,SdkError,services::LocalServiceTargetConsent};
use nestlink_server::{AppState,router};
use nestlink_storage::{Store,StorageError};
use std::{path::PathBuf,time::{SystemTime,UNIX_EPOCH}};

type Result<T=()> = std::result::Result<T,Box<dyn std::error::Error+Send+Sync>>;
const PASSWORD: &str = "explicit-service-edge-group-test-password";
const TOTAL_BYTES: u64 = 100_000;
fn now() -> Result<u64> { Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().try_into()?) }
fn status<T>(result: std::result::Result<T,SdkError>, expected: u16) {
    assert!(matches!(result,Err(SdkError::Api(status,_)) if status.as_u16()==expected));
}
struct Server(Option<tokio::task::JoinHandle<std::io::Result<()>>>);
impl Drop for Server { fn drop(&mut self) { if let Some(worker)=self.0.as_ref() {worker.abort();} } }
struct Node {identity:NodeIdentity,lease:NodeLeaseClaims}
struct Fixture {
    _server:Server,_directory:tempfile::TempDir,database:PathBuf,deployment:String,origin:String,
    service_issuer:[u8;32],policy_issuer:[u8;32],sdk:Sdk,stranger:Sdk,host:DeviceIdentity,
    service:ServiceView,nodes:Vec<Node>,
}
async fn login(origin:&str,deployment:&str,issuer:[u8;32],name:&str)->Result<Sdk> {
    let mut sdk=Sdk::connect(origin,DeploymentTrust{deployment_id:deployment.into(),permit_issuer:issuer},true).await?;
    sdk.login(name.into(),Secret::from_text(PASSWORD.into()),None).await?;Ok(sdk)
}
async fn approve(sdk:&Sdk,host:&DeviceIdentity,definition:ServiceDefinition)->Result<ServiceView> {
    let pending=sdk.create_service(&ServiceCreate{id:random_id(),definition}).await?;
    let protocol=match pending.definition.requested_ingress {ServiceIngress::Tcp{..}=>"tcp",ServiceIngress::Udp{..}=>"udp",_=>"http"};
    let consent=LocalServiceTargetConsent::from_local_choice(&pending,protocol,"127.0.0.1:8080".parse()?)?;
    Ok(sdk.approve_service_target(host,&consent,60_000).await?)
}
impl Fixture {
    async fn new(web:bool)->Result<Self> {
        let directory=tempfile::tempdir()?;let database=directory.path().join("service-edge-groups.sqlite3");
        let deployment=random_id();let signer=PermitSigner::generate();let issuer=signer.public_key();
        let service_issuer=signer.service_lease_signer()?.public_key();let policy_issuer=signer.node_policy_signer()?.public_key();
        let vault=VaultKey::from_bytes([49;32]);let dummy=hash_password("unused-edge-group-login-dummy")?;
        let mut store=Store::open(&database,&deployment)?;store.bootstrap_admin("owner",PASSWORD)?;
        let actor=store.login("owner",PASSWORD,None,now()?/1000,&vault,&dummy)?.principal;
        store.apply_policy(store.policy()?.0,NetworkPolicy{server_forwarding:ServerForwarding::Allow,
            peer_path_mode:PeerPathMode::DirectOnly,public_ingress:PublicIngress::Enabled})?;
        let mut nodes=Vec::new();
        for index in 0..4 {
            let identity=NodeIdentity::generate();let id=random_id();
            store.register_node(&actor,NodeRegistration{id:id.clone(),name:format!("edge {index}"),
                public_key:URL_SAFE_NO_PAD.encode(identity.public_key()),roles:vec![NodeRole::NodeEdge as i32],
                max_connections:16,bytes_per_second:1_048_576})?;
            store.set_service_edge_namespace(&actor,&id,ServiceEdgeNamespaceUpdate{expected_revision:0,config:ServiceEdgeNamespace{
                service_suffix:"svc.example.test".into(),management_hostname:"control.example.test".into(),
                public_ports:vec![29100,29101],quic_address:format!("127.0.0.1:{}",29196+index)}},now()?/1000)?;
            let challenge=store.node_challenge(&id,now()?)?;
            let lease=store.issue_node_lease(&identity.prove(&challenge,&random_id())?,now()?)?;
            nodes.push(Node{identity,lease});
        }
        nodes.sort_by(|left,right|left.lease.node_id.cmp(&right.lease.node_id));
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let origin=format!("http://{}",listener.local_addr()?);
        let app=router(AppState::new(store,vault,signer,origin.clone(),false)?);
        let server=Server(Some(tokio::spawn(async move{axum::serve(listener,app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await})));
        let sdk=login(&origin,&deployment,issuer,"owner").await?;
        sdk.create_account("stranger".into(),Secret::from_text(PASSWORD.into())).await?;
        let stranger=login(&origin,&deployment,issuer,"stranger").await?;
        let host=DeviceIdentity::generate();sdk.enroll(&host,"group target".into(),"windows".into(),vec!["host".into(),"vp8".into()],"direct_only".into()).await?;
        let service=approve(&sdk,&host,ServiceDefinition{name:"one approved target".into(),host_device_id:host.device_id.clone(),
            edge_node_id:nodes[0].lease.node_id.clone(),requested_ingress:if web {ServiceIngress::Http{hostname:"app.svc.example.test".into()}}else{ServiceIngress::Tcp{port:29100}},
            allowed_sources:vec![ServiceSourceNetwork{address:"127.0.0.1".into(),prefix:32}],
            limits:ServiceLimits{maximum_connections:8,bytes_per_second:65_536,maximum_bytes:TOTAL_BYTES,idle_timeout_seconds:5}}).await?;
        Ok(Self{_server:server,_directory:directory,database,deployment,origin,service_issuer,policy_issuer,sdk,stranger,host,service,nodes})
    }
    fn update(&self,service:&ServiceView,first:usize)->Result<ServiceEdgeGroupUpdate> {
        Ok(ServiceEdgeGroupUpdate{group_version:1,expected_revision:0,expected_service_revision:service.revision,
            public_ips:vec!["127.0.0.10".parse()?],members:self.nodes[first..first+2].iter().enumerate().map(|(index,node)|
                Ok(ServiceEdgeGroupMember{node_id:node.lease.node_id.clone(),namespace_revision:1,
                    ingress_ip:format!("127.0.0.{}",first+index+2).parse()?,
                    limits:ServiceLimits{maximum_connections:4,bytes_per_second:32_768,maximum_bytes:TOTAL_BYTES/2,idle_timeout_seconds:5}})).collect::<Result<_>>()?})
    }
    async fn configure(&self)->Result<(ServiceEdgeGroupView,ServiceGroupPublicationRequest)> {
        let group=self.sdk.set_service_edge_group(&self.service.id,&self.update(&self.service,0)?).await?;
        let request=request(&group)?;Ok((group,request))
    }
    async fn usage(&self,scope:ServiceQuotaScope,key:&str)->Result<ServiceQuotaUsageView> {
        Ok(self.sdk.service_quota_usage(ServiceQuotaUsageQuery{scope,scope_key:key.into()}).await?)
    }
    async fn poll(&self,index:usize,sequence:u64)->Result<nestlink_identity::service_plane::VerifiedServiceSnapshot> {
        let node=&self.nodes[index];let at=now()?;
        let query=node.identity.sign_service_query(&NodeResourceQueryClaims{schema_version:SCHEMA_VERSION,
            deployment_id:self.deployment.clone(),security_epoch:node.lease.security_epoch,policy_revision:node.lease.policy_revision,
            node_id:node.lease.node_id.clone(),runtime_id:node.lease.runtime_id.clone(),runtime_generation:node.lease.runtime_generation,
            lease_sequence:node.lease.lease_sequence,request_id:random_id(),request_sequence:sequence,
            issued_at_unix_ms:at,expires_at_unix_ms:(at+SERVICE_RESOURCE_MS.min(NODE_RESOURCE_TTL_MS)).min(node.lease.expires_at_unix_ms)})?;
        let result:ServiceResourceGrant=reqwest::Client::new().post(format!("{}/api/v3/nodes/{}/service-resources",self.origin,node.lease.node_id))
            .json(&query).send().await?.error_for_status()?.json().await?;
        Ok(verify_service_snapshot(&result.snapshot,&self.policy_issuer,&query,&node.identity.public_key())?)
    }
    fn reopen(&self)->Result<Store> { Ok(Store::open_existing(&self.database,&self.deployment)?) }
    async fn shutdown(mut self)->Result {
        if let Some(worker)=self._server.0.take() {worker.abort();let _=worker.await;}
        self._directory.close()?;Ok(())
    }
}
fn request(group:&ServiceEdgeGroupView)->Result<ServiceGroupPublicationRequest> {
    Ok(ServiceGroupPublicationRequest{group_version:1,group_id:group.group_id.clone(),expected_group_revision:group.revision,
        expected_service_revision:group.service_revision,aggregate_sha256:service_edge_group_digest(group)?})
}
fn usage_grants(grant:&ServiceGroupPublicationGrant,issuer:&[u8;32])->Result<Vec<ServiceUsageBudgetGrantClaims>> {
    grant.members.iter().map(|member|{
        let lease=verify_service_lease(&member.lease,issuer)?;
        Ok(verify_service_usage_budget_grant(&lease.claims().usage_grant,issuer)?)
    }).collect()
}

#[tokio::test]
async fn real_http_reserves_one_partitioned_budget_and_node_renewal_never_reserves_again()->Result {
    let f=Fixture::new(false).await?;let(group,body)=f.configure().await?;
    let grant=f.sdk.publish_service_group(&f.service.id,&body).await?;
    assert_eq!(grant.group,group);let budgets=usage_grants(&grant,&f.service_issuer)?;
    assert_eq!(budgets.len(),2);assert_ne!(budgets[0].grant_id,budgets[1].grant_id);
    assert_ne!(budgets[0].publication_id,budgets[1].publication_id);
    assert_eq!(budgets.iter().map(|budget|budget.byte_ceiling).sum::<u64>(),TOTAL_BYTES);
    for (index,member) in grant.members.iter().enumerate() {
        let lease=verify_service_lease(&member.lease,&f.service_issuer)?;let claims=lease.claims();
        assert_eq!(claims.definition,f.service.definition);assert_eq!(claims.edge_node_id(),f.nodes[index].lease.node_id);
        assert_eq!(claims.effective_limits(),group.members[index].limits);
        assert_eq!(budgets[index].edge_node_id,f.nodes[index].lease.node_id);
        let snapshot=f.poll(index,1).await?;assert_eq!(snapshot.leases().len(),1);
        assert_eq!(snapshot.leases()[0].claims().usage_grant,claims.usage_grant);
    }
    let again=f.sdk.publish_service_group(&f.service.id,&body).await?;
    assert_eq!(usage_grants(&again,&f.service_issuer)?,budgets);
    let read=f.sdk.service_group_publication(&f.service.id).await?;
    assert_eq!(usage_grants(&read,&f.service_issuer)?,budgets);
    for(scope,key)in[(ServiceQuotaScope::Account,f.service.account_id.as_str()),(ServiceQuotaScope::Device,f.host.device_id.as_str()),(ServiceQuotaScope::Resource,f.service.id.as_str())] {
        let usage=f.usage(scope,key).await?;assert_eq!(usage.outstanding_bytes,TOTAL_BYTES);assert_eq!(usage.active_grants,2);
    }
    for node in &f.nodes[..2] {let usage=f.usage(ServiceQuotaScope::Node,&node.lease.node_id).await?;assert_eq!(usage.outstanding_bytes,TOTAL_BYTES/2);assert_eq!(usage.active_grants,1);}
    let actor=f.sdk.principal().ok_or("missing owner")?;let mut reopened=f.reopen()?;
    assert_eq!(reopened.service_edge_group(actor,&f.service.id,now()?)?,group);
    assert_eq!(reopened.service_quota_usage(actor,ServiceQuotaUsageQuery{scope:ServiceQuotaScope::Resource,scope_key:f.service.id.clone()},now()?)?.outstanding_bytes,TOTAL_BYTES);
    drop(reopened);f.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn insufficient_second_member_rolls_back_every_first_member_promise_and_scope()->Result {
    let f=Fixture::new(false).await?;let(_,body)=f.configure().await?;
    let key=f.nodes[1].lease.node_id.clone();
    f.sdk.set_service_quota_limit(ServiceQuotaLimitUpdate{scope:ServiceQuotaScope::Node,scope_key:key.clone(),expected_revision:0,limit_bytes:TOTAL_BYTES/2-1}).await?;
    status(f.sdk.publish_service_group(&f.service.id,&body).await,429);
    for(scope,key)in[(ServiceQuotaScope::Account,f.service.account_id.as_str()),(ServiceQuotaScope::Device,f.host.device_id.as_str()),(ServiceQuotaScope::Resource,f.service.id.as_str()),(ServiceQuotaScope::Node,f.nodes[0].lease.node_id.as_str())] {
        let usage=f.usage(scope,key).await?;assert_eq!(usage.outstanding_bytes,0);assert_eq!(usage.active_grants,0);assert_eq!(usage.spent_bytes,0);
    }
    f.sdk.set_service_quota_limit(ServiceQuotaLimitUpdate{scope:ServiceQuotaScope::Node,scope_key:key,expected_revision:1,limit_bytes:TOTAL_BYTES/2}).await?;
    let result=f.sdk.publish_service_group(&f.service.id,&body).await?;
    assert_eq!(usage_grants(&result,&f.service_issuer)?.iter().map(|budget|budget.byte_ceiling).sum::<u64>(),TOTAL_BYTES);
    f.sdk.stop_service_group_publication(&f.service.id,&body).await?;
    status(f.sdk.publish_service_group(&f.service.id,&body).await,429);
    assert_eq!(f.usage(ServiceQuotaScope::Resource,&f.service.id).await?.outstanding_bytes,TOTAL_BYTES);
    assert!(f.poll(0,1).await?.leases().is_empty());assert!(f.poll(1,1).await?.leases().is_empty());
    // Reopening or creating a new control lifetime cannot erase old promises.
    let mut reopened=f.reopen()?;let life=reopened.service_lifecycle(now()?)?;
    assert!(matches!(reopened.publish_service_group(&life,f.sdk.principal().ok_or("missing owner")?,&f.service.id,body,
        &nestlink_identity::service_plane::ServiceLeaseSigner::from_master_seed(&[19;32])?,now()?),Err(StorageError::RateLimited)));
    drop(reopened);f.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn group_owner_namespace_and_revocation_bindings_are_enforced_over_http()->Result {
    let f=Fixture::new(true).await?;let(group,body)=f.configure().await?;
    status(f.stranger.publish_service_group(&f.service.id,&body).await,403);
    status(f.stranger.revoke_service_edge_group(&f.service.id,group.revision).await,403);
    let mut stale=body.clone();stale.expected_group_revision+=1;
    status(f.sdk.publish_service_group(&f.service.id,&stale).await,409);
    let mut wrong=body.clone();wrong.aggregate_sha256[0]^=1;
    status(f.sdk.publish_service_group(&f.service.id,&wrong).await,409);
    f.sdk.publish_service_group(&f.service.id,&body).await?;
    let mut definition=f.service.definition.clone();definition.edge_node_id=f.nodes[2].lease.node_id.clone();
    let second=approve(&f.sdk,&f.host,definition).await?;
    let other=f.sdk.set_service_edge_group(&second.id,&f.update(&second,2)?).await?;
    status(f.sdk.publish_service_group(&second.id,&request(&other)?).await,409);
    assert_eq!(f.usage(ServiceQuotaScope::Resource,&second.id).await?.outstanding_bytes,0);
    assert_eq!(f.usage(ServiceQuotaScope::Account,&f.service.account_id).await?.outstanding_bytes,TOTAL_BYTES);
    f.sdk.revoke_service_edge_group(&f.service.id,group.revision).await?;
    f.sdk.revoke_service_edge_group(&f.service.id,group.revision).await?;
    status(f.sdk.service_edge_group(&f.service.id).await,403);
    status(f.sdk.service_group_publication(&f.service.id).await,403);
    status(f.sdk.publish_service_group(&second.id,&request(&other)?).await,409);
    assert!(f.poll(0,1).await?.leases().is_empty());assert!(f.poll(1,1).await?.leases().is_empty());
    assert_eq!(f.usage(ServiceQuotaScope::Resource,&f.service.id).await?.outstanding_bytes,TOTAL_BYTES);
    f.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn each_actual_edge_report_charges_the_same_account_device_resource_and_only_its_node()->Result {
    let f=Fixture::new(false).await?;let(_,body)=f.configure().await?;
    let grant=f.sdk.publish_service_group(&f.service.id,&body).await?;let budgets=usage_grants(&grant,&f.service_issuer)?;
    for(index,budget)in budgets.iter().enumerate() {
        let node=&f.nodes[index];let report=ServiceUsageReportClaims{schema_version:SCHEMA_VERSION,deployment_id:f.deployment.clone(),
            security_epoch:budget.security_epoch,policy_revision:budget.policy_revision,account_id:budget.account_id.clone(),
            host_device_id:budget.host_device_id.clone(),service_id:budget.service_id.clone(),node_id:node.lease.node_id.clone(),
            node_runtime_id:node.lease.runtime_id.clone(),node_runtime_generation:node.lease.runtime_generation,
            grant_id:budget.grant_id.clone(),grant_sha256:digest(&verify_service_lease(&grant.members[index].lease,&f.service_issuer)?.claims().usage_grant.claims),
            publication_id:budget.publication_id.clone(),publication_generation:budget.publication_generation,report_sequence:1,
            admitted_bytes:100*(index as u64+1),opened_connections:1,closed_connections:1,sampled_at_unix_ms:now()?};
        let signed=node.identity.sign_service_usage(&report)?;
        let url=format!("{}/api/v3/nodes/{}/service-usage",f.origin,node.lease.node_id);
        let client=reqwest::Client::new();
        let ack:SignedServiceUsageReportAck=client.post(&url).json(&signed).send().await?.error_for_status()?.json().await?;
        let verified=verify_service_usage_ack(&ack,&f.policy_issuer)?;assert_eq!(verified.report_sha256,digest(&signed.claims));
        let repeated:SignedServiceUsageReportAck=client.post(&url).json(&signed).send().await?.error_for_status()?.json().await?;
        assert_eq!(ack.claims,repeated.claims);assert_eq!(ack.signature,repeated.signature);
    }
    for(scope,key)in[(ServiceQuotaScope::Account,f.service.account_id.as_str()),(ServiceQuotaScope::Device,f.host.device_id.as_str()),(ServiceQuotaScope::Resource,f.service.id.as_str())] {
        let usage=f.usage(scope,key).await?;assert_eq!(usage.spent_bytes,300);assert_eq!(usage.outstanding_bytes,TOTAL_BYTES-300);
    }
    for(index,node)in f.nodes[..2].iter().enumerate() {assert_eq!(f.usage(ServiceQuotaScope::Node,&node.lease.node_id).await?.spent_bytes,100*(index as u64+1));}
    f.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn restarted_edge_cannot_reclaim_its_old_slice_while_healthy_member_keeps_the_original_grant()->Result {
    let mut f=Fixture::new(false).await?;let(group,body)=f.configure().await?;
    let grant=f.sdk.publish_service_group(&f.service.id,&body).await?;let budgets=usage_grants(&grant,&f.service_issuer)?;
    let mut reopened=f.reopen()?;
    let challenge=reopened.node_challenge(&f.nodes[1].lease.node_id,now()?)?;
    let restarted=reopened.issue_node_lease(&f.nodes[1].identity.prove(&challenge,&random_id())?,now()?)?;
    assert!(f.poll(1,1).await.is_err());
    f.nodes[1].lease=restarted;
    assert!(f.poll(1,1).await?.leases().is_empty());
    let healthy=f.poll(0,1).await?;assert_eq!(healthy.leases().len(),1);
    assert_eq!(verify_service_usage_budget_grant(&healthy.leases()[0].claims().usage_grant,&f.service_issuer)?,budgets[0]);
    status(f.sdk.publish_service_group(&f.service.id,&body).await,409);
    assert_eq!(f.usage(ServiceQuotaScope::Resource,&f.service.id).await?.outstanding_bytes,TOTAL_BYTES);
    assert_eq!(f.sdk.service(&f.service.id).await?.publication,ServicePublicationStatus::Published);
    // Namespace replacement invalidates the complete immutable group, even on
    // its healthy node. Reconfiguration cannot refill the old unsealed slices.
    let actor=f.sdk.principal().ok_or("missing owner")?;
    let namespace=reopened.service_edge_namespace(actor,&f.nodes[1].lease.node_id,now()?/1000)?;
    reopened.set_service_edge_namespace(actor,&f.nodes[1].lease.node_id,ServiceEdgeNamespaceUpdate{expected_revision:namespace.revision,config:namespace.config},now()?/1000)?;
    assert!(f.poll(0,2).await?.leases().is_empty());
    status(f.sdk.service_edge_group(&f.service.id).await,403);
    let mut update=f.update(&f.service,0)?;update.expected_revision=group.revision;update.members[1].namespace_revision=2;
    let next=f.sdk.set_service_edge_group(&f.service.id,&update).await?;
    assert_eq!(next.group_id,group.group_id);assert_eq!(next.revision,group.revision+1);
    status(f.sdk.publish_service_group(&f.service.id,&request(&next)?).await,429);
    assert_eq!(f.usage(ServiceQuotaScope::Resource,&f.service.id).await?.outstanding_bytes,TOTAL_BYTES);
    drop(reopened);f.shutdown().await?;
    Ok(())
}
