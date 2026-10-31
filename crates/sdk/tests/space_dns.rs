//! Actual signed SDK connection -> HTTP authority -> Hickory UDP/TCP sockets.
use axum::{body::{Body, to_bytes}, extract::{Request, State}, middleware::{self, Next}, response::Response};
use hickory_server::proto::{op::{Message, MessageType, OpCode, Query, ResponseCode}, rr::{Name, RData, RecordType}};
use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_protocol::{network::SpaceRole, spaces::{*, addressing::*}};
use nestlink_sdk::{DeploymentTrust, DeviceIdentity, Sdk, SpaceDns};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use std::{net::SocketAddr, sync::{Arc, atomic::{AtomicU8, Ordering}}, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream, UdpSocket}, sync::RwLock};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PASSWORD: &str = "dns-real-http-integration-password";
const LIMIT: Duration = Duration::from_secs(3);

struct Server(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Server { fn drop(&mut self) { self.0.abort(); } }

struct Fixture {
    owner: Arc<RwLock<Sdk>>,
    member: Arc<RwLock<Sdk>>,
    owner_device: String,
    member_account: String,
    directory: SpaceAddressDirectory,
    fault: Arc<AtomicU8>,
    _server: Server,
}

async fn fault_directory(State(fault): State<Arc<AtomicU8>>, request: Request, next: Next) -> Response {
    let directory = request.uri().path().ends_with("/addressing");
    let mode = if directory { fault.load(Ordering::SeqCst) } else { 0 };
    if mode == 1 { tokio::time::sleep(Duration::from_millis(1500)).await; }
    let response = next.run(request).await;
    if mode < 2 || !response.status().is_success() { return response; }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, 4 * 1024 * 1024).await else { return Response::new(Body::empty()); };
    let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(&bytes) else { return Response::new(Body::empty()); };
    match mode {
        2 => json["space"]["observed_at_unix_ms"] = serde_json::json!(1),
        3 => json["space"]["space_id"] = serde_json::json!(random_id()),
        4 => json["suffix"] = serde_json::json!("local"),
        5 => {
            if let Some(row) = json["addresses"].as_array().and_then(|rows| rows.iter().find(|row| row["name"] == "owner")).cloned()
                && let Some(rows) = json["addresses"].as_array_mut() { rows.push(row); }
        }
        6 => {
            if let Some(rows) = json["addresses"].as_array_mut()
                && let Some(row) = rows.iter_mut().find(|row| row["name"] == "owner") {
                row["ipv4"] = serde_json::json!("8.8.8.8");
            }
        }
        7 => json["cache_max_age_seconds"] = serde_json::json!(60),
        _ => {}
    }
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    match serde_json::to_vec(&json) {
        Ok(bytes) => Response::from_parts(parts, Body::from(bytes)),
        Err(_) => Response::new(Body::empty()),
    }
}

impl Fixture {
    async fn new() -> Result<Self> {
        let deployment = random_id();
        let signer = PermitSigner::generate();
        let issuer = signer.public_key();
        let mut store = Store::in_memory(&deployment)?;
        store.bootstrap_admin("owner", PASSWORD)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let fault = Arc::new(AtomicU8::new(0));
        let app = router(AppState::new(store, VaultKey::from_bytes([92; 32]), signer, origin.clone(), false)?)
            .layer(middleware::from_fn_with_state(fault.clone(), fault_directory));
        let server = Server(tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
        }));
        let mut owner = Sdk::connect(&origin, DeploymentTrust { deployment_id: deployment.clone(), permit_issuer: issuer }, true).await?;
        owner.login("owner".into(), Secret::from_text(PASSWORD.into()), None).await?;
        owner.create_account("member".into(), Secret::from_text(PASSWORD.into())).await?;
        let mut member = Sdk::connect(&origin, DeploymentTrust { deployment_id: deployment, permit_issuer: issuer }, true).await?;
        member.login("member".into(), Secret::from_text(PASSWORD.into()), None).await?;
        let member_account = member.principal().ok_or("member not signed in")?.account_id.clone();
        let owner_device = DeviceIdentity::generate();
        let member_device = DeviceIdentity::generate();
        owner.enroll(&owner_device, "Owner".into(), "linux-x11".into(), vec!["controller".into()], "direct_preferred".into()).await?;
        member.enroll(&member_device, "Member".into(), "windows".into(), vec!["controller".into()], "direct_preferred".into()).await?;
        let space = owner.create_space(SpaceCreateRequest { name: "DNS HTTP".into() }).await?;
        let invitation = owner.invite_to_space(&space.space_id, SpaceInvitationRequest {
            expected_revision: space.revision, role: SpaceRole::Member, target_account_id: Some(member_account.clone()), expires_at_unix_ms: space.observed_at_unix_ms + 60_000,
        }).await?;
        let joined = member.accept_space_invitation(&space.space_id, &invitation.invitation.invitation_id, SpaceInvitationAcceptance { token: invitation.token }).await?;
        let joined = member.join_space_device(&space.space_id, SpaceDeviceJoin { expected_revision: joined.revision, expected_membership_epoch: 0, installation_id: member_device.device_id.clone() }).await?;
        owner.join_space_device(&space.space_id, SpaceDeviceJoin { expected_revision: joined.revision, expected_membership_epoch: 0, installation_id: owner_device.device_id.clone() }).await?;
        let first = owner.issue_space_address(&space.space_id, SpaceAddressIssue {
            expected_revision: 0, expected_address_epoch: 0, expected_membership_epoch: 1, installation_id: owner_device.device_id.clone(), name: "owner".into(),
        }).await?;
        let directory = owner.issue_space_address(&space.space_id, SpaceAddressIssue {
            expected_revision: first.revision, expected_address_epoch: 0, expected_membership_epoch: 1, installation_id: member_device.device_id, name: "member".into(),
        }).await?;
        Ok(Self { owner: Arc::new(RwLock::new(owner)), member: Arc::new(RwLock::new(member)), owner_device: owner_device.device_id, member_account, directory, fault, _server: server })
    }
    async fn start(&self, member: bool) -> Result<SpaceDns> {
        Ok(SpaceDns::start(if member { self.member.clone() } else { self.owner.clone() }, &self.directory.space.space_id, "127.0.0.1:0".parse()?).await?)
    }
    fn name(&self, label: &str) -> String { format!("{label}.{}", self.directory.suffix) }
}

fn query(name: &str, kind: RecordType) -> Result<Message> {
    let mut message = Message::new(1729, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(Name::from_ascii(name)?, kind));
    Ok(message)
}

async fn udp(address: SocketAddr, message: Message) -> Result<Message> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(address).await?;
    socket.send(&message.to_vec()?).await?;
    let mut bytes = [0; 4096];
    let length = tokio::time::timeout(LIMIT, socket.recv(&mut bytes)).await??;
    let response = Message::from_vec(&bytes[..length])?;
    assert_eq!(response.metadata.id, message.metadata.id);
    Ok(response)
}

async fn tcp(address: SocketAddr, message: Message) -> Result<Message> {
    let mut socket = TcpStream::connect(address).await?;
    let bytes = message.to_vec()?;
    socket.write_u16(u16::try_from(bytes.len())?).await?;
    socket.write_all(&bytes).await?;
    let length = tokio::time::timeout(LIMIT, socket.read_u16()).await??;
    let mut bytes = vec![0; usize::from(length)];
    tokio::time::timeout(LIMIT, socket.read_exact(&mut bytes)).await??;
    Ok(Message::from_vec(&bytes)?)
}

async fn rebind(address: SocketAddr) -> Result {
    tokio::time::timeout(LIMIT, async {
        loop {
            if let Ok(udp) = UdpSocket::bind(address).await
                && let Ok(tcp) = TcpListener::bind(address).await { drop((udp, tcp)); return; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await?;
    Ok(())
}

#[tokio::test]
async fn ordinary_member_and_admin_dns_remain_same_account_over_udp_and_tcp() -> Result {
    let f = Fixture::new().await?;
    assert_eq!(f.directory.addresses.len(), 2, "admin receives both accounts from the real HTTP directory");
    let mut admin = f.start(false).await?;
    let mut member = f.start(true).await?;
    for (dns, own, other) in [(&admin, "owner", "member"), (&member, "member", "owner")] {
        let a = udp(dns.local_addr(), query(&f.name(own), RecordType::A)?).await?;
        assert_eq!(a.metadata.response_code, ResponseCode::NoError);
        assert!(a.metadata.authoritative && !a.metadata.recursion_available);
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.answers[0].ttl(), 0);
        assert!(matches!(a.answers[0].data(), RData::A(_)));
        let aaaa = tcp(dns.local_addr(), query(&f.name(own).to_uppercase(), RecordType::AAAA)?).await?;
        assert_eq!(aaaa.metadata.response_code, ResponseCode::NoError);
        assert!(matches!(aaaa.answers[0].data(), RData::AAAA(_)));
        let hidden = udp(dns.local_addr(), query(&f.name(other), RecordType::A)?).await?;
        assert_eq!(hidden.metadata.response_code, ResponseCode::NXDomain);
        assert!(hidden.answers.is_empty() && hidden.authorities.is_empty());
    }
    admin.shutdown().await?;
    member.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn unrelated_local_cross_space_multiquestion_and_zone_transfer_are_refused() -> Result {
    let f = Fixture::new().await?;
    let mut dns = f.start(false).await?;
    for name in ["printer.local".into(), "example.com".into(), format!("owner.s-{}.nestlink.internal", random_id()), format!("nested.{}", f.name("owner"))] {
        assert_eq!(udp(dns.local_addr(), query(&name, RecordType::A)?).await?.metadata.response_code, ResponseCode::Refused);
    }
    for kind in [RecordType::ANY, RecordType::AXFR] {
        assert_eq!(tcp(dns.local_addr(), query(&f.name("owner"), kind)?).await?.metadata.response_code, ResponseCode::Refused);
    }
    let mut multiple = query(&f.name("owner"), RecordType::A)?;
    multiple.add_query(Query::query(Name::from_ascii(f.name("owner"))?, RecordType::AAAA));
    assert_eq!(udp(dns.local_addr(), multiple).await?.metadata.response_code, ResponseCode::FormErr);
    dns.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn rename_and_revocation_have_no_stale_dns_cache() -> Result {
    let f = Fixture::new().await?;
    let mut dns = f.start(false).await?;
    assert_eq!(udp(dns.local_addr(), query(&f.name("owner"), RecordType::A)?).await?.answers.len(), 1);
    let renamed = f.owner.read().await.rename_space_address(&f.directory.space.space_id, &f.owner_device, SpaceAddressRename {
        expected_revision: f.directory.revision, expected_address_epoch: 1, name: "files".into(),
    }).await?;
    assert_eq!(udp(dns.local_addr(), query(&f.name("owner"), RecordType::A)?).await?.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(tcp(dns.local_addr(), query(&f.name("files"), RecordType::AAAA)?).await?.answers.len(), 1);
    f.owner.read().await.revoke_space_address(&f.directory.space.space_id, &f.owner_device, SpaceAddressRevocation {
        expected_revision: renamed.revision, expected_address_epoch: 2,
    }).await?;
    assert_eq!(udp(dns.local_addr(), query(&f.name("files"), RecordType::A)?).await?.metadata.response_code, ResponseCode::NXDomain);
    dns.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn member_removal_and_session_logout_close_both_transports() -> Result {
    let f = Fixture::new().await?;
    let mut member = f.start(true).await?;
    let address = member.local_addr();
    let current = f.owner.read().await.space_details(&f.directory.space.space_id).await?;
    f.owner.read().await.remove_space_member(&f.directory.space.space_id, &f.member_account, SpaceMemberRemoval { expected_revision: current.space.revision, expected_member_epoch: 1 }).await?;
    assert!(tokio::time::timeout(LIMIT, member.wait()).await?.is_err());
    rebind(address).await?;
    let mut admin = f.start(false).await?;
    let address = admin.local_addr();
    f.owner.write().await.forget_login();
    assert!(tokio::time::timeout(LIMIT, admin.wait()).await?.is_err());
    rebind(address).await?;
    Ok(())
}

#[tokio::test]
async fn dropping_owner_aborts_idle_tcp_and_releases_udp_and_tcp_ports() -> Result {
    let f = Fixture::new().await?;
    let dns = f.start(false).await?;
    let address = dns.local_addr();
    let mut idle = TcpStream::connect(address).await?;
    drop(dns);
    let mut byte = [0];
    assert!(tokio::time::timeout(LIMIT, idle.read(&mut byte)).await?.is_ok());
    rebind(address).await?;
    Ok(())
}

#[tokio::test]
async fn cancelling_shutdown_retains_the_task_until_wait_or_drop_reclaims_both_sockets() -> Result {
    use std::{future::{Future, poll_fn}, task::Poll};
    let f = Fixture::new().await?;
    for join in [true, false] {
        let mut dns = f.start(false).await?;
        let address = dns.local_addr();
        {
            let mut shutdown = Box::pin(dns.shutdown());
            poll_fn(|cx| {
                assert!(shutdown.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            }).await;
        }
        assert!(!dns.is_finished(), "canceled shutdown must retain the still-owned task");
        if join { dns.wait().await?; }
        drop(dns);
        rebind(address).await?;
    }
    Ok(())
}

#[tokio::test]
async fn delayed_authority_fails_closed_and_stops_instead_of_using_previous_answers() -> Result {
    let f = Fixture::new().await?;
    let mut dns = f.start(false).await?;
    let address = dns.local_addr();
    assert_eq!(udp(address, query(&f.name("owner"), RecordType::A)?).await?.answers.len(), 1);
    f.fault.store(1, Ordering::SeqCst);
    assert!(tokio::time::timeout(LIMIT, dns.wait()).await?.is_err());
    rebind(address).await?;
    Ok(())
}

#[tokio::test]
async fn stale_forged_duplicate_and_out_of_pool_http_directory_responses_are_rejected() -> Result {
    let f = Fixture::new().await?;
    for mode in 2..=7 {
        f.fault.store(mode, Ordering::SeqCst);
        assert!(f.start(false).await.is_err(), "directory fault {mode}");
    }
    Ok(())
}

#[tokio::test]
async fn authorization_failure_seen_by_query_is_reported_as_failure_after_cleanup() -> Result {
    let f = Fixture::new().await?;
    let mut dns = f.start(false).await?;
    let address = dns.local_addr();
    f.fault.store(2, Ordering::SeqCst);
    let _ = udp(address, query(&f.name("owner"), RecordType::A)?).await;
    dns.request_shutdown();
    assert!(tokio::time::timeout(LIMIT, dns.wait()).await?.is_err(), "explicit cleanup must preserve the first authorization failure");
    rebind(address).await?;
    Ok(())
}

#[tokio::test]
async fn public_bind_and_another_selected_space_are_not_admitted() -> Result {
    let f = Fixture::new().await?;
    assert!(SpaceDns::start(f.owner.clone(), &f.directory.space.space_id, "0.0.0.0:0".parse()?).await.is_err());
    assert!(SpaceDns::start(f.member.clone(), &random_id(), "127.0.0.1:0".parse()?).await.is_err());
    Ok(())
}

#[tokio::test]
async fn replacing_the_shared_sdk_account_and_refreshing_the_session_terminate_the_owner() -> Result {
    let f = Fixture::new().await?;
    let mut dns = f.start(false).await?;
    let address = dns.local_addr();
    {
        let mut owner = f.owner.write().await;
        let mut member = f.member.write().await;
        std::mem::swap(&mut *owner, &mut *member);
    }
    assert!(tokio::time::timeout(LIMIT, dns.wait()).await?.is_err());
    rebind(address).await?;
    let mut dns = f.start(true).await?;
    let address = dns.local_addr();
    f.member.write().await.refresh().await?;
    assert!(tokio::time::timeout(LIMIT, dns.wait()).await?.is_err());
    rebind(address).await?;
    Ok(())
}
