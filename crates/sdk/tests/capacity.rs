//! Bounded hosted load on the original HTTP, private-service QUIC/TCP and ledger
//! paths. Installations are real enrolled SDK identities in one space; they are
//! not 100 physical machines or 100 independently running relay processes.
#![cfg(target_os = "linux")]

use nestlink_auth::{Secret, VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_protocol::{api::*, service_plane::*, services::private::*, spaces::*};
use nestlink_sdk::{
    DeploymentTrust, DeviceIdentity, Sdk,
    services::{LocalServiceTargetConsent, PrivateServiceHost, PrivateServiceHostConfig},
};
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use serde_json::json;
use std::{
    io::Write,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, watch},
    task::JoinSet,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const NODES: usize = 100;
const PAIRS: usize = 20;
const FLOWS: usize = 50;
const WAVES: usize = 3;
const PASSWORD: &str = "hosted-capacity-explicit-lab-password";

fn wall_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

fn record(value: serde_json::Value) -> Result {
    let path =
        std::env::var_os("NESTLINK_CAPACITY_SAMPLES").ok_or("missing retained sample path")?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{value}")?;
    file.flush()?;
    Ok(())
}

fn resource_sample(stage: &str) -> Result {
    record(json!({"stage":stage,"at_unix_ms":wall_ms()?,
        "open_descriptors":std::fs::read_dir("/proc/self/fd")?.count(),
        "process_status":std::fs::read_to_string("/proc/self/status")?
            .lines().filter(|line| ["VmRSS:","VmHWM:","Threads:"].iter().any(|key|line.starts_with(key)))
            .collect::<Vec<_>>()}))
}

struct Abort<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Backend {
    address: SocketAddr,
    active: Arc<AtomicUsize>,
    completed: Arc<AtomicUsize>,
    task: Abort<std::io::Result<()>>,
}
impl Backend {
    async fn start(pair: usize) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let active = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let count = active.clone();
        let done = completed.clone();
        let task = Abort(tokio::spawn(async move {
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut stream, _) = accepted?;
                        let count = count.clone();
                        let done = done.clone();
                        workers.spawn(async move {
                            let mut payload = [0;16];
                            stream.read_exact(&mut payload).await?;
                            assert_eq!(u32::from_be_bytes([payload[4],payload[5],payload[6],payload[7]]), pair as u32);
                            assert_eq!(&payload[12..], b"NLCP");
                            count.fetch_add(1,Ordering::SeqCst);
                            stream.write_all(&payload).await?;
                            let mut end = [0;1];
                            assert_eq!(stream.read(&mut end).await?,0,"unexpected replay or extra target bytes");
                            stream.shutdown().await?;
                            count.fetch_sub(1,Ordering::SeqCst);
                            done.fetch_add(1,Ordering::SeqCst);
                            Ok::<_,std::io::Error>(())
                        });
                    }
                    Some(joined) = workers.join_next(), if !workers.is_empty() => { joined??; }
                }
            }
        }));
        Ok(Self {
            address,
            active,
            completed,
            task,
        })
    }
}

struct Pair {
    client: Arc<Sdk>,
    consumer: Arc<DeviceIdentity>,
    view: ServiceView,
    exposure: ServiceExposureView,
    host: PrivateServiceHost,
    backend: Backend,
}

impl Pair {
    fn request(&self, consumer: &DeviceIdentity) -> PrivateServiceAccessRequest {
        PrivateServiceAccessRequest {
            request_id: random_id(),
            consumer_device_id: consumer.device_id.clone(),
            expected_service_revision: self.view.revision,
            expected_exposure_revision: self.exposure.revision,
            maximum_bytes: 4096,
            route: PrivateServiceRouteRequest::Direct,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit hosted capacity workflow retains build, samples and failures"]
async fn hundred_enrolled_nodes_twenty_pairs_thousand_simultaneous_authorized_streams() -> Result {
    assert_eq!(
        std::env::var("RUNNER_ENVIRONMENT").as_deref(),
        Ok("github-hosted")
    );
    tokio::time::timeout(Duration::from_secs(600), capacity()).await??;
    Ok(())
}

async fn capacity() -> Result {
    resource_sample("before_setup")?;
    let directory = tempfile::tempdir()?;
    let deployment = random_id();
    let signer = PermitSigner::generate();
    let issuer = signer.public_key();
    let mut store = Store::open(&directory.path().join("management.sqlite3"), &deployment)?;
    store.bootstrap_admin("admin", PASSWORD)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let app = router(AppState::new(
        store,
        VaultKey::from_bytes([124; 32]),
        signer,
        origin.clone(),
        false,
    )?);
    let _server = Abort(tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    }));
    let mut sdk = Sdk::connect(
        &origin,
        DeploymentTrust {
            deployment_id: deployment.clone(),
            permit_issuer: issuer,
        },
        true,
    )
    .await?;
    sdk.login("admin".into(), Secret::from_text(PASSWORD.into()), None)
        .await?;
    let sdk = Arc::new(sdk);
    let mut space = sdk
        .create_space(SpaceCreateRequest {
            name: "100 enrolled capacity installations".into(),
        })
        .await?;
    let mut devices = Vec::with_capacity(NODES);
    for index in 0..NODES {
        // Setup honors the original 30 space operations per login per minute.
        // No rate bucket, production deadline or admission rule is overridden.
        if index > 0 && index % 20 == 0 {
            tokio::time::sleep(Duration::from_secs(61)).await;
        }
        let device = Arc::new(DeviceIdentity::generate());
        sdk.enroll(
            &device,
            format!("capacity-{index}"),
            "linux-x11".into(),
            vec!["host".into(), "vp8".into()],
            "direct_only".into(),
        )
        .await?;
        space = sdk
            .join_space_device(
                &space.space_id,
                SpaceDeviceJoin {
                    expected_revision: space.revision,
                    expected_membership_epoch: 0,
                    installation_id: device.device_id.clone(),
                },
            )
            .await?;
        devices.push(device);
    }
    let details = sdk.space_details(&space.space_id).await?;
    assert_eq!(
        details
            .devices
            .iter()
            .filter(|device| device.active)
            .count(),
        NODES
    );
    // A separately enrolled identity belongs to another space, despite sharing
    // the lab administrator's login. Neither account ownership nor membership
    // in another space can replace the exact private-service ACL.
    let foreign = DeviceIdentity::generate();
    sdk.enroll(
        &foreign,
        "other-space installation".into(),
        "linux-x11".into(),
        vec!["host".into()],
        "direct_only".into(),
    )
    .await?;
    let other = sdk
        .create_space(SpaceCreateRequest {
            name: "isolated other capacity space".into(),
        })
        .await?;
    sdk.join_space_device(
        &other.space_id,
        SpaceDeviceJoin {
            expected_revision: other.revision,
            expected_membership_epoch: 0,
            installation_id: foreign.device_id.clone(),
        },
    )
    .await?;
    let mut pairs = Vec::with_capacity(PAIRS);
    for index in 0..PAIRS {
        let mut client = Sdk::connect(
            &origin,
            DeploymentTrust {
                deployment_id: deployment.clone(),
                permit_issuer: issuer,
            },
            true,
        )
        .await?;
        client
            .login("admin".into(), Secret::from_text(PASSWORD.into()), None)
            .await?;
        let backend = Backend::start(index).await?;
        let pending = sdk
            .create_service(&ServiceCreate {
                id: random_id(),
                definition: ServiceDefinition {
                    name: format!("capacity exact target {index}"),
                    host_device_id: devices[index * 2].device_id.clone(),
                    edge_node_id: String::new(),
                    requested_ingress: ServiceIngress::Tcp { port: 29100 },
                    allowed_sources: vec![],
                    limits: ServiceLimits {
                        maximum_connections: FLOWS.try_into()?,
                        bytes_per_second: 16 * 1024 * 1024,
                        maximum_bytes: 16 * 1024 * 1024,
                        idle_timeout_seconds: 30,
                    },
                },
            })
            .await?;
        let consent =
            LocalServiceTargetConsent::from_local_choice(&pending, "tcp", backend.address)?;
        let view = sdk
            .approve_service_target(&devices[index * 2], &consent, 3_600_000)
            .await?;
        let exposure = sdk
            .set_service_exposure(
                &view.id,
                ServiceExposureUpdate {
                    expected_revision: 0,
                    expected_service_revision: view.revision,
                    space_id: space.space_id.clone(),
                    mode: ServiceAccessMode::Private,
                    private_maximum_bytes: 16 * 1024 * 1024,
                    public_maximum_bytes: 0,
                },
            )
            .await?;
        sdk.grant_private_service(
            &view.id,
            PrivateServiceAclUpdate {
                expected_exposure_revision: exposure.revision,
                subject: PrivateServiceSubject::Installation {
                    installation_id: devices[index * 2 + 1].device_id.clone(),
                },
                expires_at_unix_ms: wall_ms()? + 3_600_000,
            },
        )
        .await?;
        let host = sdk
            .start_private_service_host(
                devices[index * 2].clone(),
                consent,
                PrivateServiceHostConfig {
                    listen: "127.0.0.1:0".parse()?,
                    advertised_ip: "127.0.0.1".parse()?,
                    usage_directory: directory.path().join(format!("host-{index}")),
                },
            )
            .await?;
        pairs.push(Pair {
            client: Arc::new(client),
            consumer: devices[index * 2 + 1].clone(),
            view,
            exposure,
            host,
            backend,
        });
    }
    for pair in pairs.iter().take(3) {
        assert!(
            sdk.request_private_service(&pair.view.id, pair.request(&devices[99]))
                .await
                .is_err()
        );
        assert!(
            sdk.request_private_service(&pair.view.id, pair.request(&foreign))
                .await
                .is_err()
        );
    }
    resource_sample("all_hosts_ready")?;
    for wave in 0..WAVES {
        let started = Instant::now();
        let (release, released) = watch::channel(false);
        let (ready, mut readiness) = mpsc::channel(PAIRS * FLOWS);
        let mut workers = JoinSet::new();
        for (index, pair) in pairs.iter().enumerate() {
            for flow in 0..FLOWS {
                let sdk = pair.client.clone();
                let consumer = pair.consumer.clone();
                let service = pair.view.id.clone();
                let request = pair.request(&consumer);
                let ready = ready.clone();
                let mut released = released.clone();
                workers.spawn(async move {
                    let start = Instant::now();
                    let lease = sdk.request_private_service(&service, request).await?;
                    let mut connection = sdk.connect_private_service(&consumer, lease).await?;
                    let mut payload = [0; 16];
                    payload[..4].copy_from_slice(&(wave as u32).to_be_bytes());
                    payload[4..8].copy_from_slice(&(index as u32).to_be_bytes());
                    payload[8..12].copy_from_slice(&(flow as u32).to_be_bytes());
                    payload[12..].copy_from_slice(b"NLCP");
                    connection.stream()?.write_all(&payload).await?;
                    let mut echo = [0; 16];
                    connection.stream()?.read_exact(&mut echo).await?;
                    assert_eq!(
                        echo, payload,
                        "wrong pair, stale generation or payload corruption"
                    );
                    ready
                        .send((index, flow, start.elapsed().as_micros()))
                        .await?;
                    while !*released.borrow() {
                        released.changed().await?;
                    }
                    connection.stream()?.shutdown().await?;
                    let mut end = [0; 1];
                    assert_eq!(connection.stream()?.read(&mut end).await?, 0);
                    connection.close().await?;
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                });
            }
        }
        drop(ready);
        let mut opened = 0;
        while opened < PAIRS * FLOWS {
            tokio::select! {
                sample = readiness.recv() => {
                    let (pair,flow,microseconds) = sample.ok_or("capacity readiness channel ended early")?;
                    record(json!({"stage":"flow_ready","wave":wave,"pair":pair,"flow":flow,"open_microseconds":microseconds}))?;
                    opened+=1;
                }
                Some(joined) = workers.join_next() => {joined??;return Err("flow ended before all 1000 were live".into());}
            }
        }
        assert_eq!(
            pairs
                .iter()
                .map(|pair| pair.backend.active.load(Ordering::SeqCst))
                .sum::<usize>(),
            PAIRS * FLOWS
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            pairs
                .iter()
                .map(|pair| pair.backend.active.load(Ordering::SeqCst))
                .sum::<usize>(),
            PAIRS * FLOWS,
            "original authority or connection expired while holding the full offered load"
        );
        resource_sample("thousand_live_streams")?;
        record(
            json!({"stage":"wave_live","wave":wave,"registered_space_installations":NODES,
            "pairs":PAIRS,"simultaneous_actual_tcp_targets":opened,"held_seconds":2,
            "open_seconds":started.elapsed().as_secs_f64()}),
        )?;
        release.send_replace(true);
        while let Some(joined) = workers.join_next().await {
            joined??;
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while pairs
                .iter()
                .any(|pair| pair.backend.active.load(Ordering::SeqCst) != 0)
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        for pair in &pairs {
            assert_eq!(
                pair.backend.completed.load(Ordering::SeqCst),
                (wave + 1) * FLOWS
            );
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let usage = sdk
                        .service_quota_usage(ServiceQuotaUsageQuery {
                            scope: ServiceQuotaScope::Resource,
                            scope_key: pair.view.id.clone(),
                        })
                        .await?;
                    if usage.outstanding_bytes == 0 {
                        assert_eq!(usage.active_grants, 0);
                        assert_eq!(usage.spent_bytes, ((wave + 1) * FLOWS * 32) as u64);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            })
            .await??;
        }
        resource_sample("wave_drained")?;
    }
    for mut pair in pairs {
        let address = pair.host.address();
        pair.host.wait_stopped().await?;
        drop(pair.host);
        drop(std::net::UdpSocket::bind(address)?);
        assert_eq!(pair.backend.active.load(Ordering::SeqCst), 0);
        // Abort the dedicated target listener only after every real stream has
        // reached its original EOF and the service owner returned its receipt.
        pair.backend.task.0.abort();
        let joined = (&mut pair.backend.task.0).await;
        assert!(
            matches!(joined,Err(error) if error.is_cancelled()),
            "target loop did not acknowledge cancellation"
        );
        drop(std::net::TcpListener::bind(pair.backend.address)?);
    }
    resource_sample("all_owned_listeners_physically_released")?;
    record(
        json!({"stage":"complete","normal_streams":PAIRS*FLOWS*WAVES,
        "limitations":["single hosted process using real HTTP, kernel QUIC and TCP owners",
            "resource samples retained; a short load test does not qualify cross-day soak or all queues",
            "100 space installations; not 100 physical devices or relay runtimes"]}),
    )?;
    Ok(())
}
