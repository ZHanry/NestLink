use axum::{Router, body::Bytes, routing::post};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_auth::{Secret, VaultKey, hash_password, random_id};
use nestlink_identity::{
    PermitSigner, nodes::NodeIdentity, service_plane::group::service_edge_group_digest,
};
use nestlink_node::control::{NodeConfig, NodeControl};
use nestlink_protocol::{
    NodeRole,
    api::*,
    service_plane::{ServiceQuotaScope, ServiceQuotaUsageQuery, group::*, publication::*},
};
use nestlink_sdk::{
    DeploymentTrust, DeviceIdentity, Sdk,
    services::{
        HttpsBackendTls, LocalServiceGroupChoice, LocalServiceGroupRuntime,
        LocalServiceTargetConsent, ServiceGroupHostWait,
    },
};
use nestlink_server::{
    AppState, router,
    service_edge::{
        self,
        caddy::{CaddyAdmin, CaddyEdgeGroupConfig, CaddyServiceConfig},
        frontdoor::{FixedIngressConfig, FixedIngressHealth},
    },
};
use nestlink_storage::Store;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::watch,
    task::JoinSet,
};

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PASSWORD: &str = "hosted-group-original-owner-fixture";
const VIP: &str = "11.254.2.10";
const HOSTNAME: &str = "application.svc.nestlink.test";
const BYTES: u64 = 8_388_608;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EdgeConfig {
    node_id: String,
    seed: [u8; 32],
    namespace: ServiceEdgeNamespaceView,
    caddy: CaddyServiceConfig,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    deployment: String,
    policy_issuer: String,
    protocol: String,
    group: ServiceEdgeGroupView,
    edges: Vec<EdgeConfig>,
}
struct Abort<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn wall() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn write(path: &Path, value: &impl Serialize) -> Result {
    nestlink_platform_security::create_private(path, &serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(
        &nestlink_platform_security::read_private(path, 128 * 1024)?,
    )?)
}
async fn exists(path: &Path) -> Result {
    loop {
        if path.try_exists()? {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
pub async fn run() -> Result {
    let directory = PathBuf::from(
        std::env::var_os("NESTLINK_GROUP_L2_DIRECTORY").ok_or("fixture directory missing")?,
    );
    nestlink_platform_security::check_private_directory(&directory)?;
    match std::env::var("NESTLINK_GROUP_L2_ROLE")?.as_str() {
        "coordinator" => coordinator(&directory).await,
        "edge" => edge(&directory).await,
        _ => Err("unknown cooperation role".into()),
    }
}

async fn coordinator(directory: &Path) -> Result {
    eprintln!("group_l2_stage=coordinator_initialize");
    let protocol = std::env::var("NESTLINK_GROUP_L2_PROTOCOL")?;
    if !["http", "https", "tcp", "udp"].contains(&protocol.as_str()) {
        return Err("unknown protocol".into());
    }
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let policy_issuer = URL_SAFE_NO_PAD.encode(signer.node_policy_signer()?.public_key());
    let vault = VaultKey::from_bytes([47; 32]);
    let dummy = hash_password("unused-group-l2-dummy")?;
    let mut store = Store::open(&directory.join("management.sqlite3"), &deployment)?;
    eprintln!("group_l2_stage=bootstrap_admin");
    store.bootstrap_admin("admin", PASSWORD)?;
    let admin = store
        .login("admin", PASSWORD, None, wall()?, &vault, &dummy)?
        .principal;
    let mut node_ids = vec![random_id(), random_id()];
    node_ids.sort();
    let mut namespaces = Vec::new();
    for (index, id) in node_ids.iter().enumerate() {
        eprintln!("group_l2_stage=register_node member_index={index}");
        let identity = NodeIdentity::from_seed(&[151 + index as u8; 32]);
        store.register_node(
            &admin,
            NodeRegistration {
                id: id.clone(),
                name: format!("hosted group edge {}", index + 1),
                public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
                roles: vec![NodeRole::NodeEdge as i32],
                max_connections: 128,
                bytes_per_second: 2_097_152,
            },
        )?;
        eprintln!("group_l2_stage=set_node_namespace member_index={index}");
        namespaces.push(store.set_service_edge_namespace(
            &admin,
            id,
            ServiceEdgeNamespaceUpdate {
                expected_revision: 0,
                config: ServiceEdgeNamespace {
                    service_suffix: "svc.nestlink.test".into(),
                    management_hostname: "control.nestlink.test".into(),
                    public_ports: vec![29100],
                    quic_address: format!("10.244.1.{}:29199", 11 + index),
                },
            },
            wall()?,
        )?);
    }
    let listener = TcpListener::bind("0.0.0.0:29200").await?;
    let origin = "http://127.0.0.1:29200".to_owned();
    let app = router(AppState::new(store, vault, signer, origin.clone(), false)?);
    let _server = Abort(tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    }));
    eprintln!("group_l2_stage=connect_original_sdk");
    let mut sdk = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id: deployment.clone(),
            permit_issuer: issuer,
        },
        true,
    )
    .await?;
    eprintln!("group_l2_stage=login_original_account");
    sdk.login("admin".into(), Secret::from_text(PASSWORD.into()), None)
        .await?;
    eprintln!("group_l2_stage=set_original_network_policy");
    sdk.set_policy(PolicyUpdate {
        expected_revision: 1,
        policy: NetworkPolicy {
            server_forwarding: "allow".into(),
            peer_path_mode: "direct_only".into(),
            public_ingress: "enabled".into(),
        },
    })
    .await?;
    let host = Arc::new(DeviceIdentity::generate());
    eprintln!("group_l2_stage=enroll_original_host");
    sdk.enroll(
        &host,
        "real fixed group target".into(),
        "linux-x11".into(),
        vec!["host".into(), "vp8".into()],
        "direct_only".into(),
    )
    .await?;
    let observed = Arc::new(AtomicU64::new(0));
    let backend = Backend::start(&protocol, observed.clone()).await?;
    eprintln!("group_l2_stage=create_original_service");
    let definition = sdk
        .create_service(&ServiceCreate {
            id: random_id(),
            definition: ServiceDefinition {
                name: format!("real dual-edge {protocol}"),
                host_device_id: host.device_id.clone(),
                edge_node_id: node_ids[0].clone(),
                requested_ingress: match protocol.as_str() {
                    "http" => ServiceIngress::Http {
                        hostname: HOSTNAME.into(),
                    },
                    "https" => ServiceIngress::Https {
                        hostname: HOSTNAME.into(),
                    },
                    "tcp" => ServiceIngress::Tcp { port: 29100 },
                    "udp" => ServiceIngress::Udp { port: 29100 },
                    _ => unreachable!(),
                },
                allowed_sources: vec![ServiceSourceNetwork {
                    address: "10.244.2.2".into(),
                    prefix: 32,
                }],
                limits: ServiceLimits {
                    maximum_connections: 64,
                    bytes_per_second: 1_048_576,
                    maximum_bytes: BYTES,
                    idle_timeout_seconds: 5,
                },
            },
        })
        .await?;
    let mut consent =
        LocalServiceTargetConsent::from_local_choice(&definition, &protocol, backend.address)?;
    if let Some(tls) = backend.tls.as_ref() {
        consent = consent.with_https_backend_tls(tls.clone())?;
    }
    eprintln!("group_l2_stage=approve_original_fixed_target");
    let approved = sdk.approve_service_target(&host, &consent, 180_000).await?;
    eprintln!("group_l2_stage=set_exact_edge_group");
    let group = sdk
        .set_service_edge_group(
            &definition.id,
            &ServiceEdgeGroupUpdate {
                group_version: 1,
                expected_revision: 0,
                expected_service_revision: approved.revision,
                public_ips: vec![VIP.parse()?],
                members: node_ids
                    .iter()
                    .enumerate()
                    .map(|(index, node)| {
                        Ok(ServiceEdgeGroupMember {
                            node_id: node.clone(),
                            namespace_revision: namespaces[index].revision,
                            ingress_ip: format!("10.244.1.{}", 11 + index).parse()?,
                            limits: ServiceLimits {
                                maximum_connections: 32,
                                bytes_per_second: 524_288,
                                maximum_bytes: BYTES / 2,
                                idle_timeout_seconds: 5,
                            },
                        })
                    })
                    .collect::<Result<_>>()?,
            },
        )
        .await?;
    let digest = service_edge_group_digest(&group)?;
    let mut edges = Vec::new();
    for (index, namespace) in namespaces.into_iter().enumerate() {
        eprintln!("group_l2_stage=export_original_caddy_bootstrap member_index={index}");
        let local = directory.join(format!("edge{}", index + 1));
        nestlink_platform_security::new_private_directory(&local)?;
        let caddy = CaddyServiceConfig {
            deployment_id: deployment.clone(),
            admin: CaddyAdmin::LoopbackHttp {
                address: "127.0.0.1:2019".parse()?,
            },
            public_ips: group.public_ips.clone(),
            dns_json_endpoint: "https://doh.nestlink.test:29443/resolve".into(),
            edge_group: Some(CaddyEdgeGroupConfig {
                group_id: group.group_id.clone(),
                revision: group.revision,
                aggregate_sha256: digest,
                ingress_ip: group.members[index].ingress_ip,
                certificate: directory.join("front.pem"),
                private_key: directory.join("front.key"),
                https_root: Some(directory.join("root.der")),
            }),
        };
        let bootstrap = caddy.bootstrap(&namespace, "127.0.0.1:29200".parse()?, directory)?;
        write(&local.join("Caddy.json"), &bootstrap)?;
        edges.push(EdgeConfig {
            node_id: node_ids[index].clone(),
            seed: [151 + index as u8; 32],
            namespace,
            caddy,
        });
    }
    eprintln!("group_l2_stage=export_original_fixed_ingress_bundle");
    FixedIngressConfig {
        schema_version: 1,
        deployment_id: deployment.clone(),
        group: group.clone(),
        definition: approved.definition.clone(),
        health: node_ids
            .iter()
            .map(|id| FixedIngressHealth {
                node_id: id.clone(),
                port: 29201,
            })
            .collect(),
    }
    .write_bundle(&directory.join("frontdoor"))?;
    write(
        &directory.join("fixture.json"),
        &Fixture {
            deployment,
            policy_issuer,
            protocol: protocol.clone(),
            group: group.clone(),
            edges,
        },
    )?;
    let request = ServiceGroupPublicationRequest {
        group_version: 1,
        group_id: group.group_id.clone(),
        expected_group_revision: group.revision,
        expected_service_revision: group.service_revision,
        aggregate_sha256: digest,
    };
    let mut selected = Some(LocalServiceGroupChoice::from_local_choice(
        &group, &consent,
    )?);
    let mut consent = Some(consent);
    let mut runtime: Option<LocalServiceGroupRuntime> = None;
    let mut expected_business = true;
    // Only the SIGKILL experiment sets this. Unknown old commitments are never
    // turned into a fabricated drain receipt or assigned to the healthy edge.
    let mut crashed_member: Option<(usize, u64, u64)> = None;
    for sequence in 1..=8 {
        let command = directory.join(format!("command-{sequence}.json"));
        exists(&command).await?;
        let action: serde_json::Value = read(&command)?;
        eprintln!(
            "group_l2_stage=coordinator_command sequence={sequence} action={}",
            action["action"].as_str().unwrap_or("missing")
        );
        let mut finish = false;
        let result = match action["action"].as_str().ok_or("action missing")? {
            "publish" => {
                runtime = Some(
                    sdk.start_service_group_host(
                        host.clone(),
                        consent.take().ok_or("consent already consumed")?,
                        selected.take().ok_or("group choice consumed")?,
                    )
                    .await?,
                );
                assert_eq!(
                    runtime
                        .as_ref()
                        .ok_or("runtime missing")?
                        .ready_members()
                        .len(),
                    2
                );
                let grants = sdk.service_group_publication(&definition.id).await?;
                assert_eq!(grants.members.len(), 2);
                serde_json::json!({"ready_members":2,"original_partitioned_grants":2,"total_reserved_bytes":BYTES})
            }
            "publish_reject" => {
                expected_business = false;
                let (stop, cancelled) = watch::channel(false);
                let timer = tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(8)).await;
                    stop.send_replace(true);
                });
                let result = sdk
                    .start_service_group_host_cancellable(
                        host.clone(),
                        consent.take().ok_or("consent already consumed")?,
                        selected.take().ok_or("group choice consumed")?,
                        cancelled,
                    )
                    .await;
                timer.await?;
                assert!(result.is_err());
                assert_eq!(observed.load(Ordering::SeqCst), 0);
                serde_json::json!({"invalid_dns_group_revision_never_became_ready":true,"startup_cancelled_and_original_carriers_joined":true,"backend_requests":0})
            }
            "observe" => {
                serde_json::json!({"backend_requests":observed.load(Ordering::SeqCst),"ready_members":runtime.as_ref().ok_or("runtime missing")?.ready_members(),"resource_usage":sdk.service_quota_usage(ServiceQuotaUsageQuery{scope:ServiceQuotaScope::Resource,scope_key:definition.id.clone()}).await?})
            }
            "observe_crash" => {
                let index: usize = action["member_index"]
                    .as_u64()
                    .ok_or("crashed member index missing")?
                    .try_into()?;
                let node = node_ids.get(index).ok_or("crashed member index invalid")?;
                let usage = sdk
                    .service_quota_usage(ServiceQuotaUsageQuery {
                        scope: ServiceQuotaScope::Node,
                        scope_key: node.clone(),
                    })
                    .await?;
                assert!(usage.outstanding_bytes > 0);
                assert_eq!(usage.active_grants, 1);
                assert_eq!(usage.spent_bytes + usage.outstanding_bytes, BYTES / 2);
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                while runtime
                    .as_ref()
                    .ok_or("runtime missing")?
                    .ready_members()
                    .len()
                    != 1
                {
                    if tokio::time::Instant::now() >= deadline {
                        return Err("original dead-edge host authority did not expire".into());
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                crashed_member = Some((index, usage.spent_bytes, usage.outstanding_bytes));
                serde_json::json!({"crashed_member_index":index,"original_failed_node_usage":usage,"healthy_original_host_members":1,"unknown_slice_not_released_or_refilled":true})
            }
            "revoke" => {
                sdk.revoke_service_edge_group(&definition.id, group.revision)
                    .await?;
                assert!(
                    sdk.publish_service_group(&definition.id, &request)
                        .await
                        .is_err()
                );
                let runtime = runtime.as_mut().ok_or("runtime missing")?;
                loop {
                    match runtime.wait_stopped(Duration::from_secs(5)).await {
                        ServiceGroupHostWait::CleanupPending => {}
                        ServiceGroupHostWait::Stopped { members } => {
                            assert_eq!(members.len(), 2);
                            break;
                        }
                    }
                }
                serde_json::json!({"group_revoked":true,"stale_publication_rejected":true,"original_host_carriers_joined":true})
            }
            "finish" => {
                finish = true;
                let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
                let resource = loop {
                    let usage = sdk
                        .service_quota_usage(ServiceQuotaUsageQuery {
                            scope: ServiceQuotaScope::Resource,
                            scope_key: definition.id.clone(),
                        })
                        .await?;
                    let settled = if let Some((index, _, unknown)) = crashed_member {
                        let healthy = sdk
                            .service_quota_usage(ServiceQuotaUsageQuery {
                                scope: ServiceQuotaScope::Node,
                                scope_key: node_ids[1 - index].clone(),
                            })
                            .await?;
                        usage.outstanding_bytes == unknown
                            && usage.active_grants == 1
                            && healthy.outstanding_bytes == 0
                            && healthy.active_grants == 0
                    } else {
                        usage.outstanding_bytes == 0 && usage.active_grants == 0
                    };
                    if settled {
                        break usage;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return Err(
                            "valid original cleanup or retained unknown crash promise differs"
                                .into(),
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                };
                if expected_business {
                    assert!(resource.spent_bytes > 0);
                } else {
                    assert_eq!(resource.spent_bytes, 0);
                    assert_eq!(observed.load(Ordering::SeqCst), 0);
                }
                assert_eq!(resource.active_grants, u64::from(crashed_member.is_some()));
                let mut scopes = Vec::new();
                for (scope, key) in [
                    (ServiceQuotaScope::Account, definition.account_id.clone()),
                    (ServiceQuotaScope::Device, host.device_id.clone()),
                    (ServiceQuotaScope::Resource, definition.id.clone()),
                    (ServiceQuotaScope::Node, node_ids[0].clone()),
                    (ServiceQuotaScope::Node, node_ids[1].clone()),
                ] {
                    scopes.push(
                        sdk.service_quota_usage(ServiceQuotaUsageQuery {
                            scope,
                            scope_key: key,
                        })
                        .await?,
                    );
                }
                assert_eq!(scopes[0].spent_bytes, resource.spent_bytes);
                assert_eq!(scopes[1].spent_bytes, resource.spent_bytes);
                assert_eq!(
                    scopes[3].spent_bytes + scopes[4].spent_bytes,
                    resource.spent_bytes
                );
                for scope in &scopes[..3] {
                    assert_eq!(scope.outstanding_bytes, resource.outstanding_bytes);
                    assert_eq!(scope.active_grants, resource.active_grants);
                }
                if let Some((index, spent, unknown)) = crashed_member {
                    assert_eq!(scopes[3 + index].spent_bytes, spent);
                    assert_eq!(scopes[3 + index].outstanding_bytes, unknown);
                    assert_eq!(scopes[3 + index].active_grants, 1);
                    assert_eq!(scopes[3 + 1 - index].outstanding_bytes, 0);
                    assert_eq!(scopes[3 + 1 - index].active_grants, 0);
                    assert!(scopes[3 + 1 - index].spent_bytes > 0);
                } else {
                    assert!(
                        scopes
                            .iter()
                            .all(|scope| scope.outstanding_bytes == 0 && scope.active_grants == 0)
                    );
                    if expected_business {
                        assert!(scopes[3].spent_bytes > 0 && scopes[4].spent_bytes > 0);
                    }
                }
                let receipt = serde_json::json!({"schema_version":1,"scope":"L2 actual Linux IPVS/keepalived + dual original edge owners; isolated DNS and operator test root; no public Internet/ACME or director HA claim","protocol":protocol,"original_quota_scopes":scopes,"backend_requests":observed.load(Ordering::SeqCst),"host_carriers_joined":true,"outstanding_bytes":resource.outstanding_bytes,"failed_runtime_unsealed_promise_retained":crashed_member.is_some(),"crashed_member_index":crashed_member.map(|(index,_,_)|index),"healthy_original_grant_sealed":crashed_member.is_some()});
                write(&directory.join("physical-receipt.json"), &receipt)?;
                receipt
            }
            _ => return Err("unknown coordinator action".into()),
        };
        write(
            &directory.join(format!("ack-{sequence}.json")),
            &serde_json::json!({"sequence":sequence,"result":result}),
        )?;
        if finish {
            return Ok(());
        }
    }
    Err("coordinator command budget exhausted".into())
}

async fn edge(directory: &Path) -> Result {
    let fixture: Fixture = read(&directory.join("fixture.json"))?;
    let index: usize = std::env::var("NESTLINK_GROUP_L2_EDGE")?.parse()?;
    let config = fixture.edges.get(index).ok_or("edge index invalid")?;
    let instance = std::env::var("NESTLINK_GROUP_L2_INSTANCE")?;
    if !["initial", "restored"].contains(&instance.as_str()) {
        return Err("edge instance invalid".into());
    }
    let local = directory.join(format!("edge{}", index + 1));
    let marker = local.join(&instance);
    nestlink_platform_security::new_private_directory(&marker)?;
    let control = Arc::new(NodeControl::start(
        NodeConfig {
            deployment_id: fixture.deployment.clone(),
            node_id: config.node_id.clone(),
            control_origin: "http://127.0.0.1:29200".into(),
            trusted_policy_issuer: fixture.policy_issuer,
            identity_key_file: local.join("unused-fixture-key"),
            service_usage_directory: Some(local.join("ledger")),
            roles: vec![NodeRole::NodeEdge as i32],
            allow_loopback_http: true,
        },
        NodeIdentity::from_seed(&config.seed),
    )?);
    let cleanup = control.service_usage_cleanup()?;
    tokio::time::timeout(Duration::from_secs(12), async {
        while control.authorize(NodeRole::NodeEdge, true).is_err() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    let identity = Arc::new(NodeIdentity::from_seed(&config.seed));
    let endpoint = nestlink_transport_quic::service::listener(
        config.namespace.config.quic_address.parse()?,
        &identity,
    )?;
    let (stop, mut stopped) = watch::channel(false);
    let edge_control = control.clone();
    let namespace = config.namespace.clone();
    let caddy = config.caddy.clone();
    let bind = fixture.group.members[index].ingress_ip;
    let mut worker = tokio::spawn(async move {
        service_edge::serve_with_caddy_and_health(
            endpoint,
            edge_control,
            identity,
            namespace,
            bind,
            service_edge::ServiceEdgeIngress {
                caddy: Some(caddy),
                group_health_listen: Some(SocketAddr::new(bind, 29201)),
            },
            async move {
                while !*stopped.borrow() {
                    if stopped.changed().await.is_err() {
                        break;
                    }
                }
            },
        )
        .await
    });
    write(
        &marker.join("ready.json"),
        &serde_json::json!({"node_id":config.node_id,"instance":instance,"original_node_control_authorized":true}),
    )?;
    let stop_path = marker.join("stop.json");
    tokio::select! {result=&mut worker=>{result??;return Err("edge stopped before requested physical stop".into());},result=exists(&stop_path)=>result?,}
    stop.send_replace(true);
    worker.await??;
    assert!(
        control
            .wait_service_usage_settled(Duration::from_secs(8))
            .await?
    );
    write(
        &marker.join("stopped.json"),
        &serde_json::json!({"original_ingress_joined":true,"current_runtime_grants_settled":true,"old_runtime_grants_claimed_settled":false,"caddy_owned_by_external_fixture":true}),
    )?;
    exists(&marker.join("finish.json")).await?;
    control.stop();
    drop(control);
    tokio::time::timeout(Duration::from_secs(8), async {
        while !cleanup.is_finished() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    write(
        &marker.join("cleanup.json"),
        &serde_json::json!({"original_durable_usage_store_closed":true}),
    )?;
    Ok(())
}

struct Backend {
    address: SocketAddr,
    tls: Option<HttpsBackendTls>,
    _worker: Abort<Result>,
}
impl Backend {
    async fn start(protocol: &str, observed: Arc<AtomicU64>) -> Result<Self> {
        if protocol == "udp" {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            let address = socket.local_addr()?;
            let worker = tokio::spawn(async move {
                let mut buffer = [0; 2048];
                loop {
                    let (size, peer) = socket.recv_from(&mut buffer).await?;
                    observed.fetch_add(1, Ordering::SeqCst);
                    socket.send_to(&buffer[..size], peer).await?;
                }
            });
            return Ok(Self {
                address,
                tls: None,
                _worker: Abort(worker),
            });
        }
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        if protocol == "tcp" {
            let worker = tokio::spawn(async move {
                let mut tasks = JoinSet::new();
                loop {
                    tokio::select! {Some(result)=tasks.join_next()=>result??,accepted=listener.accept()=>{let(mut socket,_)=accepted?;let observed=observed.clone();tasks.spawn(async move{let mut bytes=Vec::new();tokio::time::timeout(Duration::from_secs(4),(&mut socket).take(2048).read_to_end(&mut bytes)).await??;observed.fetch_add(1,Ordering::SeqCst);socket.write_all(&bytes).await?;socket.shutdown().await?;Ok::<(),Box<dyn std::error::Error+Send+Sync>>(())});}}
                }
            });
            return Ok(Self {
                address,
                tls: None,
                _worker: Abort(worker),
            });
        }
        let app = Router::new().route(
            "/exchange",
            post(move |body: Bytes| {
                let observed = observed.clone();
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    body
                }
            }),
        );
        if protocol == "https" {
            let (tls, acceptor) = backend_tls()?;
            let listener = TlsListener { listener, acceptor };
            let worker = tokio::spawn(async move {
                axum::serve(listener, app).await?;
                Ok(())
            });
            Ok(Self {
                address,
                tls: Some(tls),
                _worker: Abort(worker),
            })
        } else {
            let worker = tokio::spawn(async move {
                axum::serve(listener, app).await?;
                Ok(())
            });
            Ok(Self {
                address,
                tls: None,
                _worker: Abort(worker),
            })
        }
    }
}
struct TlsListener {
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}
impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if let Ok((socket, address)) = self.listener.accept().await
                && let Ok(Ok(socket)) =
                    tokio::time::timeout(Duration::from_secs(2), self.acceptor.accept(socket)).await
            {
                return (socket, address);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}
fn backend_tls() -> Result<(HttpsBackendTls, tokio_rustls::TlsAcceptor)> {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = params.self_signed(&key)?;
    let issuer = Issuer::new(params, key);
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec!["backend.nestlink.test".into()])?;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = params.signed_by(&key, &issuer)?;
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    server.max_early_data_size = 0;
    Ok((
        HttpsBackendTls::new("backend.nestlink.test".into(), vec![ca.der().to_vec()])?,
        tokio_rustls::TlsAcceptor::from(Arc::new(server)),
    ))
}
