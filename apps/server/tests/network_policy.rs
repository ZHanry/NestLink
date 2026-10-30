//! Exercise real HTTP listeners, the shared security middleware and durable store.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{VaultKey, hash_password, random_id};
use nestlink_identity::{InstallationIdentity, PermitSigner, network::{NetworkVerification, SignedNetworkGrant, verify_network_grant}};
use nestlink_protocol::{api::{DeviceDescriptor, DeviceRegistration}, network::{GrantClaims, SpaceRole}};
use nestlink_server::{AppState, router};
use nestlink_storage::{Store, network_policy::{NetworkAuthorityUpdate, NetworkMembershipRequest, NetworkMembershipUpdate}};
use reqwest::{Client, StatusCode};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::PathBuf, time::{Duration, SystemTime, UNIX_EPOCH}};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const PASSWORD: &str = "network-api-integration-password";

struct Running(tokio::task::JoinHandle<()>);
impl Drop for Running { fn drop(&mut self) { self.0.abort(); } }

struct Fixture {
    _directory: tempfile::TempDir,
    _running: Running,
    database: PathBuf,
    deployment: String,
    origin: String,
    http: Client,
    admin_token: String,
    member_token: String,
    admin_session: String,
    admin_account: String,
    installation: String,
    device_key: [u8;32],
    issuer: [u8;32],
    space: String,
    expired_grant: Option<String>,
}

fn current_ms() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().try_into()?)
}

impl Fixture {
    async fn new(seed_expired_grant: bool) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("control.sqlite3");
        let deployment = random_id();
        let mut store = Store::open(&database,&deployment)?;
        // Seed one genuinely expired credential through the production store
        // API before the HTTP listener starts; tests never alter signed bytes.
        let now_ms = current_ms()? - if seed_expired_grant { 60_000 } else { 0 };
        let vault = VaultKey::from_bytes([7;32]);
        let dummy = hash_password("dummy-only-password")?;
        store.bootstrap_admin("admin",PASSWORD)?;
        let admin = store.login("admin",PASSWORD,None,now_ms/1000,&vault,&dummy)?;
        store.create_member(&admin.principal,"member",PASSWORD)?;
        let member = store.login("member",PASSWORD,None,now_ms/1000,&vault,&dummy)?;
        let identity = InstallationIdentity::generate();
        let installation = random_id();
        let challenge = store.enrollment_challenge(&member.principal,now_ms/1000)?;
        let mut registration = DeviceRegistration { challenge_id:challenge.id,
            device:DeviceDescriptor { id:installation.clone(),name:"network member".into(),platform:"windows".into(),
                public_key:URL_SAFE_NO_PAD.encode(identity.public_key()),capabilities:vec!["controller".into()],path_mode:"direct_preferred".into() },
            signature:String::new() };
        registration.signature = URL_SAFE_NO_PAD.encode(identity.sign_action(&store.registration_transcript(&member.principal,&registration,now_ms/1000)?)?);
        store.register_device(&member.principal,registration,now_ms/1000)?;
        let signer = PermitSigner::from_seed([44;32]);
        let network = signer.network_authority_signer()?;
        let issuer = network.public_key();
        let space = random_id();
        let expired_grant = if seed_expired_grant {
            store.configure_network_authority(&admin.principal,NetworkAuthorityUpdate {
                space_id:space.clone(),expected_revision:0,public_key:issuer,
            },now_ms)?;
            store.set_network_membership(&admin.principal,NetworkMembershipUpdate {
                space_id:space.clone(),installation_id:installation.clone(),expected_policy_revision:1,expected_membership_epoch:0,role:SpaceRole::Member,
            },now_ms)?;
            let id = random_id();
            store.issue_network_membership(&admin.principal,&network,NetworkMembershipRequest {
                space_id:space.clone(),installation_id:installation.clone(),grant_id:id.clone(),expected_policy_epoch:2,expected_membership_epoch:1,expires_at_ms:now_ms+1000,
            },now_ms)?;
            Some(id)
        } else { None };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}",listener.local_addr()?);
        let app = router(AppState::new(store,vault,signer,origin.clone(),false)?);
        let running = Running(tokio::spawn(async move { let _ = axum::serve(listener,app).await; }));
        Ok(Self { _directory:directory,_running:running,database,deployment,origin,
            http:Client::builder().timeout(Duration::from_secs(5)).redirect(reqwest::redirect::Policy::none()).build()?,
            admin_token:admin.access_token.expose().into(),member_token:member.access_token.expose().into(),
            admin_session:admin.principal.session_id,admin_account:admin.principal.account_id,
            installation,device_key:identity.public_key(),issuer,space,expired_grant })
    }
    fn base(&self) -> String { format!("/api/v3/network/spaces/{}",self.space) }
    fn member_path(&self) -> String { format!("{}/members/{}",self.base(),self.installation) }
    async fn call(&self, method: &str, path: &str, body: Value, token: Option<&str>) -> Result<(StatusCode,Value)> {
        self.call_headers(method,path,body,token,&[]).await
    }
    async fn call_headers(&self, method: &str, path: &str, body: Value, token: Option<&str>, headers: &[(&str,&str)])
        -> Result<(StatusCode,Value)> {
        let mut request = self.http.request(reqwest::Method::from_bytes(method.as_bytes())?,format!("{}{path}",self.origin)).json(&body);
        if let Some(token) = token { request = request.bearer_auth(token); }
        for (name,value) in headers { request = request.header(*name,*value); }
        let response = request.send().await?;
        assert_eq!(response.headers().get("cache-control").and_then(|v|v.to_str().ok()),Some("no-store"));
        let status = response.status();
        let bytes = response.bytes().await?;
        Ok((status,if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes)? }))
    }
    async fn setup_space(&self) -> Result {
        let (status,policy) = self.call("PUT",&format!("{}/authority",self.base()),json!({"expected_revision":0}),Some(&self.admin_token)).await?;
        assert_eq!(status,StatusCode::OK);
        assert_eq!(policy["authority_public_key"],URL_SAFE_NO_PAD.encode(self.issuer));
        assert_eq!(policy["revision"],1);
        assert!(policy.get("claims").is_none());
        let (status,member) = self.call("PUT",&self.member_path(),json!({"expected_policy_revision":1,"expected_membership_epoch":0,"role":"member"}),Some(&self.admin_token)).await?;
        assert_eq!(status,StatusCode::OK);
        assert_eq!(member["public_key"],URL_SAFE_NO_PAD.encode(self.device_key));
        assert_eq!(member["policy"]["policy_epoch"],2);
        Ok(())
    }
    async fn issue(&self, id: &str, policy_epoch: u64, membership_epoch: u64) -> Result<Value> {
        let (status,view) = self.call("POST",&format!("{}/grants",self.member_path()),json!({
            "grant_id":id,"expected_policy_epoch":policy_epoch,"expected_membership_epoch":membership_epoch,"expires_at_unix_ms":current_ms()?+60_000,
        }),Some(&self.admin_token)).await?;
        assert_eq!(status,StatusCode::CREATED,"{view}");
        Ok(view)
    }
}

fn signed(view: &Value) -> Result<SignedNetworkGrant> {
    Ok(SignedNetworkGrant {
        claims:URL_SAFE_NO_PAD.decode(view["claims"].as_str().ok_or("claims missing")?)?,
        signature:URL_SAFE_NO_PAD.decode(view["signature"].as_str().ok_or("signature missing")?)?,
    })
}

#[tokio::test]
async fn complete_admin_http_membership_lifecycle_signs_reads_revokes_and_rejoins() -> Result {
    let f = Fixture::new(false).await?;
    f.setup_space().await?;
    let id = random_id();
    let issued = f.issue(&id,2,1).await?;
    let credential = signed(&issued)?;
    let revoked = BTreeSet::new();
    let verified = verify_network_grant(&credential,&NetworkVerification {
        authority_key:&f.issuer,deployment_id:&f.deployment,space_id:&f.space,policy_epoch:2,now_ms:current_ms()?,revoked_grant_ids:&revoked,
    })?;
    let GrantClaims::Membership(member) = verified.claims() else { return Err("not membership".into()); };
    assert_eq!((member.installation_id.as_str(),member.public_key,member.membership_epoch,member.role),
        (f.installation.as_str(),f.device_key,1,SpaceRole::Member));
    let grant_path = format!("{}/grants/{id}",f.base());
    let (status,read) = f.call("GET",&grant_path,Value::Null,Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::OK);
    assert_eq!(read,issued);
    let (status,policy) = f.call("DELETE",&grant_path,json!({"expected_revision":2}),Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::OK);
    assert_eq!(policy["revision"],3);
    assert_eq!(f.call("GET",&grant_path,Value::Null,Some(&f.admin_token)).await?.0,StatusCode::FORBIDDEN);
    let (status,member) = f.call("DELETE",&f.member_path(),json!({"expected_policy_revision":3,"expected_membership_epoch":1}),Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::OK);
    assert_eq!(member["active"],false);
    assert_eq!(member["membership_epoch"],2);
    assert_eq!(member["policy"]["policy_epoch"],3);
    assert_eq!(f.call("PUT",&f.member_path(),json!({"expected_policy_revision":4,"expected_membership_epoch":1,"role":"owner"}),Some(&f.admin_token)).await?.0,StatusCode::CONFLICT);
    let (status,member) = f.call("PUT",&f.member_path(),json!({"expected_policy_revision":4,"expected_membership_epoch":2,"role":"guest"}),Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::OK);
    assert_eq!(member["membership_epoch"],3);
    assert_eq!(member["role"],"guest");
    let next = f.issue(&random_id(),4,3).await?;
    assert_ne!(next["signature"],issued["signature"]);
    assert_eq!(f.call("POST",&format!("{}/grants",f.member_path()),json!({
        "grant_id":id,"expected_policy_epoch":4,"expected_membership_epoch":3,"expires_at_unix_ms":current_ms()?+60_000,
    }),Some(&f.admin_token)).await?.0,StatusCode::CONFLICT);
    let (status,safe) = f.call("GET",&format!("{}/policy",f.base()),Value::Null,Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::OK);
    assert_eq!(safe["revision"],5);
    assert!(safe.get("claims").is_none() && safe.get("signature").is_none());
    Ok(())
}

#[tokio::test]
async fn every_network_management_route_requires_current_deployment_admin() -> Result {
    let f = Fixture::new(false).await?;
    f.setup_space().await?;
    let grant = format!("{}/grants/{}",f.base(),random_id());
    let routes = [
        ("PUT",format!("{}/authority",f.base()),json!({"expected_revision":2})),
        ("GET",format!("{}/policy",f.base()),Value::Null),
        ("GET",f.member_path(),Value::Null),
        ("PUT",f.member_path(),json!({"expected_policy_revision":2,"expected_membership_epoch":1,"role":"owner"})),
        ("DELETE",f.member_path(),json!({"expected_policy_revision":2,"expected_membership_epoch":1})),
        ("POST",format!("{}/grants",f.member_path()),json!({"grant_id":random_id(),"expected_policy_epoch":2,"expected_membership_epoch":1,"expires_at_unix_ms":current_ms()?+60_000})),
        ("GET",grant.clone(),Value::Null),
        ("DELETE",grant,json!({"expected_revision":2})),
    ];
    for (method,path,body) in routes {
        assert_eq!(f.call(method,&path,body.clone(),None).await?.0,StatusCode::UNAUTHORIZED,"{method} {path}");
        assert_eq!(f.call(method,&path,body,Some(&f.member_token)).await?.0,StatusCode::FORBIDDEN,"{method} {path}");
    }
    for cause in 0..3 {
        let f = Fixture::new(false).await?;
        f.setup_space().await?;
        let db = Connection::open(&f.database)?;
        match cause {
            0 => { db.execute("UPDATE management_sessions SET revoked=1 WHERE id=?1",[&f.admin_session])?; }
            1 => { db.execute("UPDATE management_sessions SET access_expires=unixepoch()-1 WHERE id=?1",[&f.admin_session])?; }
            _ => { db.execute("UPDATE account_security SET is_admin=0 WHERE account_id=?1",[&f.admin_account])?; }
        }
        let expected = if cause==2 { StatusCode::FORBIDDEN } else { StatusCode::UNAUTHORIZED };
        assert_eq!(f.call("GET",&format!("{}/policy",f.base()),Value::Null,Some(&f.admin_token)).await?.0,expected);
        assert_eq!(f.call("PUT",&format!("{}/authority",f.base()),json!({"expected_revision":2}),Some(&f.admin_token)).await?.0,expected);
    }
    Ok(())
}

#[tokio::test]
async fn csrf_origin_and_strict_bodies_prevent_arbitrary_authority_keys_and_claims() -> Result {
    let f = Fixture::new(false).await?;
    let path = format!("{}/authority",f.base());
    let cookie = format!("nl15_access={}",f.admin_token);
    assert_eq!(f.call_headers("PUT",&path,json!({"expected_revision":0}),None,&[("Cookie",&cookie)]).await?.0,StatusCode::FORBIDDEN);
    assert_eq!(f.call_headers("PUT",&path,json!({"expected_revision":0}),None,&[("Cookie",&cookie),("Origin","https://attacker.invalid")]).await?.0,StatusCode::FORBIDDEN);
    let (status,configured) = f.call_headers("PUT",&path,json!({"expected_revision":0}),None,&[("Cookie",&cookie),("Origin",&f.origin)]).await?;
    assert_eq!(status,StatusCode::OK);
    assert_eq!(configured["authority_public_key"],URL_SAFE_NO_PAD.encode(f.issuer));
    for forbidden in [json!({"expected_revision":1,"public_key":URL_SAFE_NO_PAD.encode([99u8;32])}),json!({"expected_revision":1,"claims":{}})] {
        assert_eq!(f.call("PUT",&path,forbidden,Some(&f.admin_token)).await?.0,StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert_eq!(f.call("PUT",&f.member_path(),json!({"expected_policy_revision":1,"expected_membership_epoch":0,"role":"member","public_key":"attacker"}),Some(&f.admin_token)).await?.0,StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(f.call("POST",&format!("{}/grants",f.member_path()),json!({"grant_id":random_id(),"expected_policy_epoch":1,"expected_membership_epoch":1,"expires_at_unix_ms":current_ms()?+60_000,"claims":{}}),Some(&f.admin_token)).await?.0,StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(f.call_headers("GET",&format!("{}/policy",f.base()),Value::Null,Some(&f.admin_token),&[("Origin","https://attacker.invalid")]).await?.0,StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn expired_credentials_unenrolled_devices_and_stale_epochs_are_rejected_over_http() -> Result {
    let expired = Fixture::new(true).await?;
    let id = expired.expired_grant.as_ref().ok_or("expired grant missing")?;
    let (status,body) = expired.call("GET",&format!("{}/grants/{id}",expired.base()),Value::Null,Some(&expired.admin_token)).await?;
    assert_eq!(status,StatusCode::FORBIDDEN);
    assert_eq!(body["code"],"LEASE_EXPIRED");
    let f = Fixture::new(false).await?;
    f.setup_space().await?;
    for (policy,member,expiry,status) in [
        (1,1,current_ms()?+60_000,StatusCode::CONFLICT),
        (2,2,current_ms()?+60_000,StatusCode::CONFLICT),
        (2,1,current_ms()?-1,StatusCode::BAD_REQUEST),
        (2,1,current_ms()?+1_000_000,StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(f.call("POST",&format!("{}/grants",f.member_path()),json!({"grant_id":random_id(),"expected_policy_epoch":policy,"expected_membership_epoch":member,"expires_at_unix_ms":expiry}),Some(&f.admin_token)).await?.0,status);
    }
    assert_eq!(f.call("PUT",&format!("{}/members/{}",f.base(),random_id()),json!({"expected_policy_revision":2,"expected_membership_epoch":0,"role":"member"}),Some(&f.admin_token)).await?.0,StatusCode::FORBIDDEN);
    assert_eq!(f.call("GET",&format!("/api/v3/network/spaces/{}/grants/{}",random_id(),random_id()),Value::Null,Some(&f.admin_token)).await?.0,StatusCode::FORBIDDEN);
    let grant = random_id();
    f.issue(&grant,2,1).await?;
    assert_eq!(f.call("DELETE",&format!("/api/v3/devices/{}",f.installation),json!({"request_id":random_id()}),Some(&f.member_token)).await?.0,StatusCode::NO_CONTENT);
    assert_eq!(f.call("GET",&format!("{}/grants/{grant}",f.base()),Value::Null,Some(&f.admin_token)).await?.0,StatusCode::FORBIDDEN);
    let (status,member) = f.call("GET",&f.member_path(),Value::Null,Some(&f.admin_token)).await?;
    assert_eq!(status,StatusCode::OK);
    assert_eq!(member["active"],false);
    Ok(())
}

#[tokio::test]
async fn rate_capacity_is_reserved_only_for_authenticated_admin_sessions() -> Result {
    let f = Fixture::new(false).await?;
    f.setup_space().await?;
    let path = format!("{}/policy",f.base());
    for index in 0..64 {
        let bearer = format!("{index:043}");
        assert_eq!(f.call("GET",&path,Value::Null,Some(&bearer)).await?.0,StatusCode::UNAUTHORIZED);
    }
    // setup_space used two slots in the same authenticated network namespace.
    for _ in 0..28 {
        assert_eq!(f.call("GET",&path,Value::Null,Some(&f.admin_token)).await?.0,StatusCode::OK);
    }
    assert_eq!(f.call("GET",&path,Value::Null,Some(&f.admin_token)).await?.0,StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}

#[tokio::test]
async fn fresh_server_state_uses_the_same_derived_authority_after_reopening_the_database() -> Result {
    let f = Fixture::new(false).await?;
    f.setup_space().await?;
    let id = random_id();
    let original = f.issue(&id,2,1).await?;
    let store = Store::open_existing(&f.database,&f.deployment)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}",listener.local_addr()?);
    let app = router(AppState::new(store,VaultKey::from_bytes([7;32]),PermitSigner::from_seed([44;32]),origin.clone(),false)?);
    let _running = Running(tokio::spawn(async move { let _ = axum::serve(listener,app).await; }));
    let response = f.http.get(format!("{origin}{}/grants/{id}",f.base())).bearer_auth(&f.admin_token).send().await?;
    assert_eq!(response.status(),StatusCode::OK);
    assert_eq!(response.json::<Value>().await?,original);
    let policy: Value = f.http.get(format!("{origin}{}/policy",f.base())).bearer_auth(&f.admin_token).send().await?.error_for_status()?.json().await?;
    assert_eq!(policy["authority_public_key"],URL_SAFE_NO_PAD.encode(f.issuer));
    let response = f.http.post(format!("{origin}{}/grants",f.member_path())).bearer_auth(&f.admin_token).json(&json!({"grant_id":random_id(),"expected_policy_epoch":2,"expected_membership_epoch":1,"expires_at_unix_ms":current_ms()?+60_000})).send().await?;
    assert_eq!(response.status(),StatusCode::CREATED);
    let probe = Connection::open(&f.database)?;
    assert_eq!(probe.query_row("SELECT count(*) FROM network_grants WHERE space_id=?1",params![f.space],|r|r.get::<_,u64>(0))?,2);
    Ok(())
}
