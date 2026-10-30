//! Real SDK and HTTP transport exercise the production metadata API.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret,VaultKey,hash_password,random_id};
use nestlink_identity::{PermitSigner,nodes::NodeIdentity};
use nestlink_protocol::{NodeRole,api::{NodeRegistration,NodeRelayAttributes,NodeRelayAttributesUpdate}};
use nestlink_sdk::{DeploymentTrust,Sdk,SdkError};
use nestlink_server::{AppState,router};
use nestlink_storage::Store;
use std::time::{Duration,SystemTime,UNIX_EPOCH};
type Result<T=()> = std::result::Result<T,Box<dyn std::error::Error+Send+Sync>>;
struct Abort(tokio::task::JoinHandle<()>);
impl Drop for Abort {fn drop(&mut self){self.0.abort();}}
const PASSWORD:&str="sdk-relay-metadata-password";

#[tokio::test]
async fn sdk_metadata_round_trip_enforces_http_authority_cas_bounds_and_legacy_registration() -> Result {
    let deployment=random_id();
    let signer=PermitSigner::generate();
    let issuer=signer.public_key();
    let vault=VaultKey::from_bytes([8;32]);
    let now=SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut store=Store::in_memory(&deployment)?;
    store.bootstrap_admin("admin",PASSWORD)?;
    let admin=store.login("admin",PASSWORD,None,now,&vault,&hash_password(PASSWORD)?)?.principal;
    store.create_member(&admin,"member",PASSWORD)?;
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin=format!("http://{}",listener.local_addr()?);
    let app=router(AppState::new(store,vault,signer,origin.clone(),false)?);
    let _server=Abort(tokio::spawn(async move {let _=axum::serve(listener,app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await;}));
    let trust=||DeploymentTrust{deployment_id:deployment.clone(),permit_issuer:issuer};
    let mut sdk=Sdk::connect(&origin,trust(),true).await?;
    let id=random_id();
    assert!(sdk.node_relay_attributes(&id).await.is_err());
    sdk.login("admin".into(),Secret::from_text(PASSWORD.into()),None).await?;
    let descriptor=NodeRegistration{id:id.clone(),name:"legacy-registration".into(),public_key:URL_SAFE_NO_PAD.encode(NodeIdentity::generate().public_key()),roles:vec![NodeRole::NodeRelay as i32],max_connections:8,bytes_per_second:1048576};
    sdk.register_node(descriptor.clone()).await?;
    let edge=NodeRegistration{id:random_id(),public_key:URL_SAFE_NO_PAD.encode(NodeIdentity::generate().public_key()),roles:vec![NodeRole::NodeEdge as i32],..descriptor.clone()};
    sdk.register_node(edge.clone()).await?;
    assert!(matches!(sdk.node_relay_attributes(&edge.id).await,Err(SdkError::Api(status,_)) if status.as_u16()==403));
    assert!(matches!(sdk.set_node_relay_attributes(&edge.id,NodeRelayAttributesUpdate{expected_revision:0,attributes:NodeRelayAttributes::default()}).await,Err(SdkError::Api(status,_)) if status.as_u16()==403));
    let initial=sdk.node_relay_attributes(&id).await?;
    assert_eq!(initial.revision,0);
    assert_eq!(initial.attributes,NodeRelayAttributes::default());
    let update=NodeRelayAttributesUpdate{expected_revision:0,attributes:NodeRelayAttributes{region:Some("eu-central".into()),cost_weight:Some(0)}};
    let first=sdk.set_node_relay_attributes(&id,update.clone()).await?;
    assert_eq!(first.revision,1);
    assert_eq!(first.attributes,update.attributes);
    assert!(matches!(sdk.set_node_relay_attributes(&id,update).await,Err(SdkError::Api(status,_)) if status.as_u16()==409));
    let current=sdk.node_relay_attributes(&id).await?;
    assert_eq!(current.revision,1);
    let http=reqwest::Client::builder().timeout(Duration::from_secs(3)).build()?;
    let login:serde_json::Value=http.post(format!("{origin}/api/v3/auth/login")).json(&serde_json::json!({"username":"admin","password":PASSWORD})).send().await?.error_for_status()?.json().await?;
    let token=login["access_token"].as_str().ok_or("token missing")?;
    let url=format!("{origin}/api/v3/nodes/{id}/relay-attributes");
    for body in [
        serde_json::json!({"expected_revision":1,"attributes":{"region":"EU","cost_weight":0}}),
        serde_json::json!({"expected_revision":1,"attributes":{"region":null,"cost_weight":1000001}}),
        serde_json::json!({"expected_revision":1,"attributes":{"region":null,"cost_weight":null,"roles":[1]}}),
    ] {
        assert!(http.put(&url).bearer_auth(token).json(&body).send().await?.status().is_client_error());
    }
    assert_eq!(http.get(&url).send().await?.status().as_u16(),401);
    let mut member=Sdk::connect(&origin,trust(),true).await?;
    member.login("member".into(),Secret::from_text(PASSWORD.into()),None).await?;
    assert!(matches!(member.node_relay_attributes(&id).await,Err(SdkError::Api(status,_)) if status.as_u16()==403));
    assert!(matches!(member.set_node_relay_attributes(&id,NodeRelayAttributesUpdate{expected_revision:1,attributes:NodeRelayAttributes::default()}).await,Err(SdkError::Api(status,_)) if status.as_u16()==403));
    let cleared=sdk.set_node_relay_attributes(&id,NodeRelayAttributesUpdate{expected_revision:1,attributes:NodeRelayAttributes::default()}).await?;
    assert_eq!(cleared.revision,2);
    assert_eq!(cleared.attributes,NodeRelayAttributes::default());
    let nodes=sdk.nodes().await?;
    let unchanged=nodes.iter().find(|node|node.node.id==id).ok_or("relay missing")?;
    assert_eq!(serde_json::to_value(&unchanged.node)?,serde_json::to_value(&descriptor)?);
    sdk.revoke_node(&id).await?;
    assert!(matches!(sdk.node_relay_attributes(&id).await,Err(SdkError::Api(status,_)) if status.as_u16()==403));
    assert!(matches!(sdk.set_node_relay_attributes(&id,NodeRelayAttributesUpdate{expected_revision:2,attributes:NodeRelayAttributes::default()}).await,Err(SdkError::Api(status,_)) if status.as_u16()==403));
    Ok(())
}
