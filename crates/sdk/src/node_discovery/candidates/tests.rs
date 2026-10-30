use super::*;
use nestlink_identity::{PermitSigner, verify_permit};
use nestlink_protocol::{NodeDiscoveryClaims, Path, Permission, PermitClaims, SignedNodeDiscovery};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn id(value: u8) -> String { format!("{value:08x}-1111-4111-8111-111111111111") }

struct Fixture {
    sdk: Sdk,
    signer: PermitSigner,
    local: DeviceIdentity,
    permit: VerifiedPermit,
}
impl Fixture {
    fn new() -> Result<Self> {
        let signer=PermitSigner::generate();
        let issuer=signer.public_key();
        let local=DeviceIdentity::generate();
        let claims=PermitClaims {
            schema_version:SCHEMA_VERSION,deployment_id:id(1),security_epoch:1,
            session_id:id(2),account_id:id(3),controller_device_id:local.device_id.clone(),
            host_device_id:id(5),controller_key_sha256:digest(&local.identity.public_key()).to_vec(),
            host_key_sha256:vec![2;32],resource_id:id(5),permissions:vec![Permission::View as i32],
            paths:vec![Path::Relay as i32],policy_revision:2,connection_generation:1,lease_sequence:1,
            issued_at_unix_ms:1_000_000,expires_at_unix_ms:1_015_000,
            capability_sha256:vec![3;32],required_capabilities:vec!["vp8".into()],..Default::default()
        };
        let permit=verify_permit(&signer.sign(&claims)?.encode_to_vec(),&issuer)?;
        let mut sdk=Sdk {
            client:Client::builder().no_proxy().build()?,origin:Url::parse("https://control.example.test")?,
            trust:DeploymentTrust{deployment_id:id(1),permit_issuer:issuer},
            health:HealthResponse{product:"NestLink".into(),version:env!("CARGO_PKG_VERSION").into(),api_base:API_BASE.into(),alpn:ALPN.into(),deployment_id:id(1),security_epoch:1,permit_issuer:URL_SAFE_NO_PAD.encode(issuer),node_policy_issuer:URL_SAFE_NO_PAD.encode(issuer),native_ice_version:0},login:None,
        };
        sdk.install_login(LoginResponse {
            principal:Principal{account_id:id(3),session_id:id(8),name:"controller".into(),is_admin:false,access_expires:9999999999},
            access_token:"A".repeat(43),refresh_token:"B".repeat(43),refresh_expires:9999999999,generation:1,
        })?;
        Ok(Self{sdk,signer,local,permit})
    }
    fn claims(&self, context: &DiscoveryRequestContext) -> Result<NodeDiscoveryClaims> {
        let p=self.permit.claims();
        let proof=discovery_transcript(p,&p.account_id,&self.local.device_id,&context.nonce)?;
        Ok(NodeDiscoveryClaims {
            schema_version:SCHEMA_VERSION,deployment_id:p.deployment_id.clone(),security_epoch:1,session_id:p.session_id.clone(),account_id:p.account_id.clone(),device_id:self.local.device_id.clone(),device_key_sha256:p.controller_key_sha256.clone(),permit_sha256:digest(&p.encode_to_vec()).to_vec(),request_sha256:digest(&proof.encode_to_vec()).to_vec(),nonce:context.nonce.to_vec(),issued_at_unix_ms:1_000_001,expires_at_unix_ms:1_005_001,
            nodes:(20..24).map(|n|DiscoveredRelayNode{node_id:id(n),node_key_sha256:vec![n;32],runtime_id:id(n+10),runtime_generation:1,endpoint_revision:1,quic_uri:format!("quic://relay-{n}.example:28743"),wss_origin:String::new(),allow_loopback:false,expires_at_unix_ms:1_005_001}).collect(),
        })
    }
    fn attributes() -> Vec<NodeRelayAttributesView> {
        [None,Some(5),Some(0),Some(5)].into_iter().enumerate().map(|(i,cost_weight)|NodeRelayAttributesView{node_id:id(20+i as u8),revision:1,attributes:NodeRelayAttributes{region:Some("eu-west".into()),cost_weight}}).collect()
    }
    fn candidates(&self) -> Result<NodeRelayCandidates> {
        let context=self.sdk.discovery_request(&self.local,&self.permit)?;
        let claims=self.claims(&context)?;
        let encoded=URL_SAFE_NO_PAD.encode(self.signer.sign_node_discovery(&claims)?.encode_to_vec());
        let discovery=self.sdk.verified_discovery_response(context,&encoded,&self.local,&self.permit)?;
        Ok(NodeRelayCandidates::new(discovery,Self::attributes())?)
    }
}

#[test]
fn checked_copies_sort_known_cost_then_unknown_and_explicit_select_uses_signed_identity() -> Result {
    let f=Fixture::new()?;
    let candidates=f.candidates()?;
    let mut sorted=candidates.checked(&f.sdk,&f.permit,&f.local)?;
    assert_eq!(sorted.iter().map(|c|c.node.node_id.clone()).collect::<Vec<_>>(),vec![id(22),id(21),id(23),id(20)]);
    assert_eq!(candidates.discovery.nodes().iter().map(|n|n.node_id.clone()).collect::<Vec<_>>(),vec![id(20),id(21),id(22),id(23)]);
    sorted[0].node.quic_uri="quic://caller-edited.example:9".into();
    assert_eq!(candidates.select(&f.sdk,&f.permit,&f.local,&id(22))?.node.quic_uri,"quic://relay-22.example:28743");
    assert!(candidates.select(&f.sdk,&f.permit,&f.local,&id(99)).is_err());
    let wrong=DeviceIdentity{device_id:f.local.device_id.clone(),identity:InstallationIdentity::generate()};
    assert!(candidates.select(&f.sdk,&f.permit,&wrong,&id(22)).is_err());
    let mut claims=f.permit.claims().clone();
    claims.connection_generation+=1;
    let newer=verify_permit(&f.signer.sign(&claims)?.encode_to_vec(),&f.signer.public_key())?;
    assert!(candidates.checked(&f.sdk,&newer,&f.local).is_err());
    Ok(())
}

#[test]
fn candidate_reuse_keeps_original_expiry_origin_issuer_and_login() -> Result {
    let mut f=Fixture::new()?;
    let mut candidates=f.candidates()?;
    candidates.discovery.started=std::time::Instant::now()-std::time::Duration::from_millis(5100);
    assert!(candidates.checked(&f.sdk,&f.permit,&f.local).is_err());
    assert!(candidates.select(&f.sdk,&f.permit,&f.local,&id(22)).is_err());
    let candidates=f.candidates()?;
    f.sdk.origin=Url::parse("https://other.example.test")?;
    assert!(candidates.checked(&f.sdk,&f.permit,&f.local).is_err());
    f.sdk.origin=Url::parse("https://control.example.test")?;
    f.sdk.login.as_mut().ok_or("login missing")?.principal.session_id=id(9);
    assert!(candidates.select(&f.sdk,&f.permit,&f.local,&id(22)).is_err());
    f.sdk.login.as_mut().ok_or("login missing")?.principal.session_id=id(8);
    f.sdk.trust.permit_issuer=PermitSigner::generate().public_key();
    assert!(candidates.checked(&f.sdk,&f.permit,&f.local).is_err());
    Ok(())
}

#[test]
fn response_validation_rejects_signature_tampering_and_unlisted_duplicate_or_invalid_attributes() -> Result {
    let f=Fixture::new()?;
    let context=f.sdk.discovery_request(&f.local,&f.permit)?;
    let claims=f.claims(&context)?;
    let mut signed=f.signer.sign_node_discovery(&claims)?;
    let mut changed=claims;
    changed.nodes[0].node_key_sha256[0]^=1;
    signed.claims=changed.encode_to_vec();
    assert!(f.sdk.verified_discovery_response(context,&URL_SAFE_NO_PAD.encode(signed.encode_to_vec()),&f.local,&f.permit).is_err());
    let context=f.sdk.discovery_request(&f.local,&f.permit)?;
    let mut changed_nonce=f.claims(&context)?;
    changed_nonce.nonce=vec![7;32];
    let signed=f.signer.sign_node_discovery(&changed_nonce)?;
    assert!(f.sdk.verified_discovery_response(context,&URL_SAFE_NO_PAD.encode(signed.encode_to_vec()),&f.local,&f.permit).is_err());
    for mode in 0..7 {
        let candidates=f.candidates()?;
        let mut attrs=candidates.attributes;
        match mode {
            0=>attrs[0].node_id=id(99),
            1=>attrs[1].node_id=attrs[0].node_id.clone(),
            2=>attrs[0].attributes.cost_weight=Some(1_000_001),
            3=>attrs[0].attributes.region=Some("EU WEST".into()),
            4=>attrs[0].revision=u64::MAX,
            5=>attrs.push(NodeRelayAttributesView{node_id:id(99),revision:0,attributes:NodeRelayAttributes::default()}),
            _=>{attrs.pop();},
        }
        assert!(NodeRelayCandidates::new(candidates.discovery,attrs).is_err());
    }
    Ok(())
}

#[test]
fn a_shorter_individual_node_deadline_does_not_inherit_the_snapshot_deadline() -> Result {
    let f=Fixture::new()?;
    let mut context=f.sdk.discovery_request(&f.local,&f.permit)?;
    let mut claims=f.claims(&context)?;
    claims.nodes[0].expires_at_unix_ms=claims.issued_at_unix_ms+1;
    context.started=std::time::Instant::now()-std::time::Duration::from_millis(10);
    let signed:SignedNodeDiscovery=f.signer.sign_node_discovery(&claims)?;
    let discovery=f.sdk.verified_discovery_response(context,&URL_SAFE_NO_PAD.encode(signed.encode_to_vec()),&f.local,&f.permit)?;
    let candidates=NodeRelayCandidates::new(discovery,Fixture::attributes())?;
    assert_eq!(candidates.checked(&f.sdk,&f.permit,&f.local)?.len(),3);
    assert!(candidates.select(&f.sdk,&f.permit,&f.local,&id(20)).is_err());
    Ok(())
}

#[tokio::test]
async fn only_explicit_unsupported_candidate_endpoint_uses_legacy_discovery_with_same_request() -> Result {
    use axum::{Json,Router,routing::post,response::IntoResponse};
    use std::sync::{Arc,atomic::{AtomicUsize,Ordering}};
    let mut f=Fixture::new()?;
    let legacy_calls=Arc::new(AtomicUsize::new(0));
    let mode=Arc::new(AtomicUsize::new(0));
    let requested=Arc::new(std::sync::Mutex::new(None::<NodeDiscoveryRequest>));
    let policy=Arc::new(f.signer);
    let permit=f.permit.claims().clone();
    let candidates_mode=mode.clone();
    let pending=requested.clone();
    let old_pending=requested.clone();
    let old_calls=legacy_calls.clone();
    let app=Router::new()
        .route("/api/v3/remote/{id}/relay/candidates",post(move |Json(request):Json<NodeDiscoveryRequest>| {
            let selected=candidates_mode.load(Ordering::SeqCst);
            let stored = pending.lock().map(|mut value| *value=Some(request)).is_ok();
            async move {
                if !stored { return StatusCode::INTERNAL_SERVER_ERROR.into_response(); }
                match selected {
                    0=>(StatusCode::NOT_FOUND,Json(ErrorResponse{code:ErrorCode::ProtocolMismatch})).into_response(),
                    1=>(StatusCode::FORBIDDEN,Json(ErrorResponse{code:ErrorCode::PermissionRequired})).into_response(),
                    _=>Json(NodeRelayCandidatesResponse{discovery:"invalid signed discovery".into(),attributes:Vec::new()}).into_response(),
                }
            }
        }))
        .route("/api/v3/remote/{id}/relay/discovery",post(move |Json(request):Json<NodeDiscoveryRequest>| {
            let calls=old_calls.clone();
            let pending=old_pending.clone();
            let signer=policy.clone();
            let p=permit.clone();
            async move {
                let expected=pending.lock().map_err(|_|StatusCode::INTERNAL_SERVER_ERROR)?.clone().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
                assert_eq!(request.nonce,expected.nonce);
                assert_eq!(request.signature,expected.signature);
                assert_eq!(request.device_id,expected.device_id);
                calls.fetch_add(1,Ordering::SeqCst);
                let nonce:[u8;32]=URL_SAFE_NO_PAD.decode(&request.nonce).map_err(|_|StatusCode::BAD_REQUEST)?.try_into().map_err(|_|StatusCode::BAD_REQUEST)?;
                let proof=discovery_transcript(&p,&p.account_id,&request.device_id,&nonce).map_err(|_|StatusCode::BAD_REQUEST)?;
                let claims=NodeDiscoveryClaims{schema_version:SCHEMA_VERSION,deployment_id:p.deployment_id.clone(),security_epoch:p.security_epoch,session_id:p.session_id.clone(),account_id:p.account_id.clone(),device_id:request.device_id,device_key_sha256:p.controller_key_sha256.clone(),permit_sha256:digest(&p.encode_to_vec()).to_vec(),request_sha256:digest(&proof.encode_to_vec()).to_vec(),nonce:nonce.to_vec(),issued_at_unix_ms:1_000_001,expires_at_unix_ms:1_005_001,nodes:vec![DiscoveredRelayNode{node_id:id(20),node_key_sha256:vec![20;32],runtime_id:id(30),runtime_generation:1,endpoint_revision:1,quic_uri:"quic://relay.example:28743".into(),wss_origin:String::new(),allow_loopback:false,expires_at_unix_ms:1_005_001}]};
                let signed=signer.sign_node_discovery(&claims).map_err(|_|StatusCode::INTERNAL_SERVER_ERROR)?;
                Ok::<_,StatusCode>(Json(NodeDiscoveryResponse{discovery:URL_SAFE_NO_PAD.encode(signed.encode_to_vec())}))
            }
        }));
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    f.sdk.origin=Url::parse(&format!("http://{}",listener.local_addr()?))?;
    let server=tokio::spawn(async move {let _=axum::serve(listener,app).await;});
    let result=async {
        let candidates=f.sdk.discover_relay_candidates(&f.local,&f.permit).await?;
        assert_eq!(candidates.checked(&f.sdk,&f.permit,&f.local)?[0].attributes.attributes,NodeRelayAttributes::default());
        assert_eq!(legacy_calls.load(Ordering::SeqCst),1);
        mode.store(1,Ordering::SeqCst);
        assert!(f.sdk.discover_relay_candidates(&f.local,&f.permit).await.is_err());
        mode.store(2,Ordering::SeqCst);
        assert!(f.sdk.discover_relay_candidates(&f.local,&f.permit).await.is_err());
        assert_eq!(legacy_calls.load(Ordering::SeqCst),1);
        Ok::<(),Box<dyn std::error::Error+Send+Sync>>(())
    }.await;
    server.abort();
    result
}
