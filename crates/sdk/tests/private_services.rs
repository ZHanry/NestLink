//! Real management authorization, installation-pinned Quinn, fixed local
//! HTTP/TCP/DNS targets, shared durable usage and physical listener release.
use hickory_server::proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_protocol::{api::*, services::private::*, spaces::*,
    service_plane::{ServiceQuotaScope, ServiceQuotaUsageQuery, ServiceUsageBudgetGrantClaims,
        SERVICE_USAGE_BYTES, decode_service_message}};
use nestlink_sdk::{DeploymentTrust, DeviceIdentity, Sdk,
    services::{LocalServiceTargetConsent, PrivateServiceHostConfig}};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::{Duration,SystemTime,UNIX_EPOCH}};
use tokio::{io::{AsyncReadExt,AsyncWriteExt}, net::{TcpListener,UdpSocket}};

type Result<T=()> = std::result::Result<T,Box<dyn std::error::Error+Send+Sync>>;
const PASSWORD:&str="private-service-real-bytes-password";
struct Abort<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Abort<T>{fn drop(&mut self){self.0.abort();}}
fn wall_ms()->Result<u64>{Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().try_into()?)}
struct Fixture {
    sdk:Arc<Sdk>, host:Arc<DeviceIdentity>, consumer:DeviceIdentity, outsider:DeviceIdentity,
    view:ServiceView, exposure:ServiceExposureView, rule:String, consent:LocalServiceTargetConsent,
    usage:PathBuf, _server:Abort<std::io::Result<()>>,
}
impl Fixture {
    async fn new(protocol:&str,target:SocketAddr)->Result<Self>{
        let deployment=random_id();let signer=PermitSigner::generate();let issuer=signer.public_key();
        let mut store=Store::in_memory(&deployment)?;store.bootstrap_admin("admin",PASSWORD)?;
        // Default public ingress remains disabled and no edge is registered.
        let http=TcpListener::bind("127.0.0.1:0").await?;
        let origin=format!("http://{}",http.local_addr()?);
        let app=router(AppState::new(store,VaultKey::from_bytes([113;32]),signer,origin.clone(),false)?);
        let server=Abort(tokio::spawn(async move{axum::serve(http,app.into_make_service_with_connect_info::<SocketAddr>()).await}));
        let mut sdk=Sdk::connect(&origin,DeploymentTrust{deployment_id:deployment,permit_issuer:issuer},true).await?;
        sdk.login("admin".into(),Secret::from_text(PASSWORD.into()),None).await?;
        let host=Arc::new(DeviceIdentity::generate());let consumer=DeviceIdentity::generate();let outsider=DeviceIdentity::generate();
        for (device,name) in [(&*host,"private-host"),(&consumer,"private-consumer"),(&outsider,"membership-only")]{
            sdk.enroll(device,name.into(),"linux".into(),vec!["host".into(),"vp8".into()],"direct_only".into()).await?;
        }
        let mut space=sdk.create_space(SpaceCreateRequest{name:"Exact private consumer ACL".into()}).await?;
        for device in [&host.device_id,&consumer.device_id,&outsider.device_id]{
            space=sdk.join_space_device(&space.space_id,SpaceDeviceJoin{expected_revision:space.revision,
                expected_membership_epoch:0,installation_id:device.clone()}).await?;
        }
        let requested_ingress=match protocol{
            "http"=>ServiceIngress::Http{hostname:"private.svc.example.test".into()},
            "udp"=>ServiceIngress::Udp{port:29100}, _=>ServiceIngress::Tcp{port:29100},
        };
        let pending=sdk.create_service(&ServiceCreate{id:random_id(),definition:ServiceDefinition{
            name:"Original local-only private target".into(),host_device_id:host.device_id.clone(),edge_node_id:String::new(),
            requested_ingress,allowed_sources:vec![],limits:ServiceLimits{maximum_connections:4,bytes_per_second:65536,
                maximum_bytes:131072,idle_timeout_seconds:5},
        }}).await?;
        let consent=LocalServiceTargetConsent::from_local_choice(&pending,protocol,target)?;
        let view=sdk.approve_service_target(&host,&consent,60000).await?;
        let exposure=sdk.set_service_exposure(&view.id,ServiceExposureUpdate{expected_revision:0,
            expected_service_revision:view.revision,space_id:space.space_id,mode:ServiceAccessMode::Private,
            private_maximum_bytes:131072,public_maximum_bytes:0}).await?;
        assert!(sdk.private_services(&consumer.device_id,None,20).await?.entries.is_empty());
        let policy=sdk.grant_private_service(&view.id,PrivateServiceAclUpdate{expected_exposure_revision:exposure.revision,
            subject:PrivateServiceSubject::Installation{installation_id:consumer.device_id.clone()},expires_at_unix_ms:wall_ms()?+50000}).await?;
        let rule=policy.rules.iter().find(|r|!r.revoked).ok_or("missing private rule")?.rule_id.clone();
        assert!(sdk.private_services(&outsider.device_id,None,20).await?.entries.is_empty());
        let usage=std::env::var_os("NESTLINK_NODE_TEST_USAGE_ROOT").map(PathBuf::from).unwrap_or_else(std::env::temp_dir)
            .join(format!("private-service-sdk-{}",random_id()));
        nestlink_platform_security::new_private_directory(&usage)?;
        Ok(Self{sdk:Arc::new(sdk),host,consumer,outsider,view,exposure,rule,consent,usage,_server:server})
    }
    fn request(&self,consumer:&DeviceIdentity)->PrivateServiceAccessRequest{
        PrivateServiceAccessRequest{request_id:random_id(),consumer_device_id:consumer.device_id.clone(),
            expected_service_revision:self.view.revision,expected_exposure_revision:self.exposure.revision,maximum_bytes:4096}
    }
}

#[tokio::test]
async fn private_tcp_preserves_half_close_without_public_edge_and_charges_original_ledgers()->Result{
    tokio::time::timeout(Duration::from_secs(25),async{
        let backend=TcpListener::bind("127.0.0.1:0").await?;let address=backend.local_addr()?;
        let backend=tokio::spawn(async move{
            let (mut stream,_)=backend.accept().await?;let mut input=Vec::new();stream.read_to_end(&mut input).await?;
            assert_eq!(input,b"private TCP request before FIN");
            tokio::time::sleep(Duration::from_millis(40)).await;
            stream.write_all(b"private late TCP response after FIN").await?;stream.shutdown().await?;
            Ok::<_,std::io::Error>(())
        });
        let f=Fixture::new("tcp",address).await?;
        let request=f.request(&f.consumer);let denied=f.request(&f.outsider);
        let mut host=f.sdk.start_private_service_host(f.host.clone(),f.consent,PrivateServiceHostConfig{
            listen:"127.0.0.1:0".parse()?,advertised_ip:"127.0.0.1".parse()?,usage_directory:f.usage.join("ledger")}).await?;
        assert!(f.sdk.request_private_service(&f.view.id,denied).await.is_err());
        let page=f.sdk.private_services(&f.consumer.device_id,None,20).await?;
        assert_eq!(page.entries.len(),1);assert_eq!(page.entries[0].availability,PrivateServiceAvailability::Ready);
        let lease=f.sdk.request_private_service(&f.view.id,request.clone()).await?;
        let retried=f.sdk.request_private_service(&f.view.id,request).await?;
        assert_eq!(lease.digest(),retried.digest());
        let grant:ServiceUsageBudgetGrantClaims=decode_service_message(&lease.lease().claims().usage_grant.claims,SERVICE_USAGE_BYTES)?;
        assert_eq!(grant.edge_node_id,f.host.device_id);
        let mut connection=f.sdk.connect_private_service(&f.consumer,lease).await?;
        connection.stream()?.write_all(b"private TCP request before FIN").await?;connection.stream()?.shutdown().await?;
        let mut reply=Vec::new();connection.stream()?.read_to_end(&mut reply).await?;
        assert_eq!(reply,b"private late TCP response after FIN");connection.close().await?;backend.await??;
        let spent=(b"private TCP request before FIN".len()+b"private late TCP response after FIN".len())as u64;
        tokio::time::timeout(Duration::from_secs(3),async{
            loop{
                let usage=f.sdk.service_quota_usage(ServiceQuotaUsageQuery{scope:ServiceQuotaScope::Resource,scope_key:f.view.id.clone()}).await?;
                if usage.outstanding_bytes==0{assert_eq!(usage.spent_bytes,spent);assert_eq!(usage.limit_bytes,131072);break;}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
        }).await??;
        for (scope,key) in [(ServiceQuotaScope::Device,f.host.device_id.clone()),(ServiceQuotaScope::Node,f.host.device_id.clone())]{
            let usage=f.sdk.service_quota_usage(ServiceQuotaUsageQuery{scope,scope_key:key}).await?;
            assert_eq!(usage.spent_bytes,spent);assert_eq!(usage.outstanding_bytes,0);
        }
        let endpoint=host.address();host.wait_stopped().await?;drop(host);
        assert_eq!(f.sdk.private_services(&f.consumer.device_id,None,20).await?.entries[0].availability,PrivateServiceAvailability::Offline);
        let rebound=std::net::UdpSocket::bind(endpoint)?;drop(rebound);
        std::fs::remove_dir_all(f.usage)?;
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
    }).await??;Ok(())
}

#[tokio::test]
async fn private_http_runs_real_http_backend_and_rejects_wrong_consumer_identity()->Result{
    tokio::time::timeout(Duration::from_secs(25),async{
        let backend=TcpListener::bind("127.0.0.1:0").await?;let address=backend.local_addr()?;
        let app=axum::Router::new().route("/fixed",axum::routing::get(||async{"HTTP through original private target"}));
        let _backend=Abort(tokio::spawn(async move{axum::serve(backend,app).await}));
        let f=Fixture::new("http",address).await?;let request=f.request(&f.consumer);
        let mut host=f.sdk.start_private_service_host(f.host.clone(),f.consent,PrivateServiceHostConfig{
            listen:"127.0.0.1:0".parse()?,advertised_ip:"127.0.0.1".parse()?,usage_directory:f.usage.join("ledger")}).await?;
        let lease=f.sdk.request_private_service(&f.view.id,request).await?;
        assert!(f.sdk.connect_private_service(&f.outsider,lease.clone()).await.is_err());
        let mut connection=f.sdk.connect_private_service(&f.consumer,lease).await?;
        connection.stream()?.write_all(b"GET /fixed HTTP/1.1\r\nHost: private.svc.example.test\r\nConnection: close\r\n\r\n").await?;
        let mut response=Vec::new();connection.stream()?.read_to_end(&mut response).await?;
        let response=String::from_utf8(response)?;assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.ends_with("HTTP through original private target"));
        connection.close().await?;let endpoint=host.address();host.wait_stopped().await?;drop(host);
        drop(std::net::UdpSocket::bind(endpoint)?);std::fs::remove_dir_all(f.usage)?;
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
    }).await??;Ok(())
}

#[tokio::test]
async fn private_udp_preserves_empty_datagrams_transports_dns_and_revokes_live_mapping()->Result{
    tokio::time::timeout(Duration::from_secs(25),async{
        let backend=UdpSocket::bind("127.0.0.1:0").await?;let address=backend.local_addr()?;
        let backend=tokio::spawn(async move{
            let mut buffer=[0;2048];let (length,peer)=backend.recv_from(&mut buffer).await?;
            assert_eq!(length,0);backend.send_to(&[],peer).await?;
            let (length,peer)=backend.recv_from(&mut buffer).await?;
            let request=Message::from_vec(&buffer[..length])?;
            assert_eq!(request.queries[0].name().to_string(),"approved.private.test.");
            let mut response=Message::new(request.metadata.id,MessageType::Response,OpCode::Query);
            response.add_query(request.queries[0].clone());response.metadata.response_code=ResponseCode::NoError;
            response.add_answer(Record::from_rdata(Name::from_ascii("approved.private.test.")?,30,
                RData::A(A("192.0.2.81".parse()?))));
            backend.send_to(&response.to_vec()?,peer).await?;
            Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
        });
        let f=Fixture::new("udp",address).await?;let request=f.request(&f.consumer);
        let mut host=f.sdk.start_private_service_host(f.host.clone(),f.consent,PrivateServiceHostConfig{
            listen:"127.0.0.1:0".parse()?,advertised_ip:"127.0.0.1".parse()?,usage_directory:f.usage.join("ledger")}).await?;
        let lease=f.sdk.request_private_service(&f.view.id,request).await?;
        let mut connection=f.sdk.connect_private_service(&f.consumer,lease).await?;
        connection.send_datagram(&[])?;assert!(connection.receive_datagram().await?.is_empty());
        assert!(connection.send_datagram(&[0;1170]).is_err());
        let mut query=Message::new(8173,MessageType::Query,OpCode::Query);
        query.add_query(Query::query(Name::from_ascii("approved.private.test.")?,RecordType::A));
        connection.send_datagram(&query.to_vec()?)?;
        let response=Message::from_vec(&connection.receive_datagram().await?)?;
        assert_eq!(response.metadata.id,8173);assert_eq!(response.metadata.response_code,ResponseCode::NoError);
        assert!(response.answers.iter().any(|r|matches!(&r.data,RData::A(A(ip)) if *ip=="192.0.2.81".parse::<std::net::Ipv4Addr>().unwrap())));
        backend.await??;
        f.sdk.revoke_private_service(&f.view.id,&f.rule,f.exposure.revision).await?;
        assert!(tokio::time::timeout(Duration::from_secs(3),connection.receive_datagram()).await?.is_err());
        assert!(f.sdk.private_services(&f.consumer.device_id,None,20).await?.entries.is_empty());
        connection.close().await?;let endpoint=host.address();host.wait_stopped().await?;drop(host);
        drop(std::net::UdpSocket::bind(endpoint)?);std::fs::remove_dir_all(f.usage)?;
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
    }).await??;Ok(())
}
