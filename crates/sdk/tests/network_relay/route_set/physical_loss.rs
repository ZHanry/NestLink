//! Explicit Actions-only production SDK fault slice. The controller process
//! outside this namespace installs actual nftables DROP, never NodeControl.stop
//! or an authenticated application close. Every ordinary endpoint poll uses
//! the same automatic migration entry as the product owner.
use super::*;
use nestlink_connectivity::continuation::QualityConstraints;
use nestlink_identity::digest;
use nestlink_platform_files::{ApprovedReadRoot, FileRoots};
use nestlink_remote::files::{FileReadClient, FileReadServer, FileReadVerifier, FileShutdown};
use serde_json::json;
use std::{fs, path::PathBuf};

const TRIALS: usize = 20;

fn fixture() -> Result<PathBuf> {
    assert_eq!(std::env::var("GITHUB_ACTIONS")?, "true");
    assert_eq!(std::env::var("RUNNER_ENVIRONMENT")?, "github-hosted");
    assert_eq!(std::env::var("GITHUB_REPOSITORY")?, "ZHanry/NestLink");
    let root = PathBuf::from(std::env::var("NESTLINK_SDK_MIGRATION_FIXTURE")?).canonicalize()?;
    let temporary = PathBuf::from(std::env::var("RUNNER_TEMP")?).canonicalize()?;
    assert!(root.starts_with(&temporary) && root != temporary);
    let actual = fs::read_link("/proc/self/ns/net")?;
    assert_ne!(
        actual.to_string_lossy(),
        std::env::var("NESTLINK_NETWORK_RUNNER_NAMESPACE")?
    );
    let status = fs::read_to_string("/proc/self/status")?;
    let uid = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or("missing uid")?;
    assert_ne!(uid.split_whitespace().nth(1), Some("0"));
    assert_ne!(uid.split_whitespace().nth(2), Some("0"));
    println!(
        "NESTLINK_SDK_MIGRATION namespace={actual:?} pid={} {uid}",
        std::process::id()
    );
    Ok(root)
}

fn publish(root: &std::path::Path, name: &str, value: &serde_json::Value) -> Result {
    let pending = root.join(format!("{name}.pending"));
    fs::write(&pending, serde_json::to_vec_pretty(value)?)?;
    fs::rename(pending, root.join(name))?;
    Ok(())
}

async fn wait_marker(root: &std::path::Path, name: &str, deadline: Instant) -> Result {
    tokio::time::timeout_at(deadline, async {
        while !root.join(name).is_file() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert_eq!(fs::read(root.join(name))?, b"observed\n");
    Ok(())
}

async fn read_file(
    client: &mut FileReadClient,
    root_id: &str,
    name: &str,
    expected: &[u8],
) -> Result {
    let mut download = client.open(&random_id(), root_id, name, 0, None).await?;
    assert_eq!(download.manifest().sha256, digest(expected));
    let mut verifier = FileReadVerifier::new(download.manifest().clone())?;
    let mut actual = Vec::new();
    while let Some(chunk) = client.next(&mut download).await? {
        verifier.accept(&chunk)?;
        actual.extend_from_slice(&chunk.data);
    }
    verifier.finish()?;
    assert!(download.source_verified());
    assert_eq!(actual, expected);
    Ok(())
}

async fn trial(root: &std::path::Path, index: usize) -> Result<serde_json::Value> {
    let mut f = Fixture::file_only().await?;
    let mut second = crate::chain::ChainNode::new(&f).await?;
    let (set, _, controller_route) = reserve(&f, &second).await?;
    let original_expiry = second.control.current_lease()?.expires_at_unix_ms;
    let group = controller_route.transport_group();
    let routes = controller_route
        .candidates()
        .map(|candidate| candidate.route_binding());
    let relay = |candidate: &nestlink_sdk::network::routed::VerifiedRemoteRouteCandidate<'_>| -> Result<SocketAddr> {
        let uri = url::Url::parse(candidate.node().endpoints.quic_uri.as_deref().ok_or("relay URI")?)?;
        Ok(SocketAddr::new(uri.host_str().ok_or("relay host")?.parse()?, uri.port().ok_or("relay port")?))
    };
    let active = relay(&controller_route.candidates()[1])?;
    let spare = relay(&controller_route.candidates()[0])?;
    assert!(active.ip().is_loopback() && spare.ip().is_loopback());
    assert_ne!(active.port(), spare.port());
    let controller_key = f.controller.identity.public_key();
    let host_key = f.host.identity.public_key();
    let host_route = f
        .sdk
        .verified_network_remote_route_set(&f.pin, &f.host, &f.permit, &controller_key, &set)
        .await?;
    let (_keep_stop, stop) = watch::channel(None);
    let (_keep_cancel, cancel) = watch::channel(false);
    let policy = AddressPolicy::new(&[])?;
    let addresses = [unused_udp()?, unused_udp()?];
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut controller, mut host) = tokio::try_join!(
        f.sdk.connect_continuing_network_remote_route_candidate(
            controller_route,
            1,
            addresses[0],
            &f.controller,
            &host_key,
            f.setup(EndpointRole::Controller, stop.clone())?,
            &policy,
            cancel.clone(),
            deadline,
            QualityConstraints::default()
        ),
        f.sdk.connect_continuing_network_remote_route_candidate(
            host_route,
            1,
            addresses[1],
            &f.host,
            &controller_key,
            f.setup(EndpointRole::Host, stop)?,
            &policy,
            cancel,
            deadline,
            QualityConstraints::default()
        ),
    )?;
    let original = controller.channels().network_connection_binding()?;
    assert_eq!(original, host.channels().network_connection_binding()?);
    let original_deadlines = [
        controller.channels().lease_control().current_deadline()?,
        host.channels().lease_control().current_deadline()?,
    ];
    let observations = [
        controller
            .channels()
            .path_observation()
            .ok_or("controller observation")?,
        host.channels()
            .path_observation()
            .ok_or("host observation")?,
    ];
    let generation = f.permit.claims().connection_generation;
    let directory = root.join(format!("source-{index:02}"));
    fs::create_dir(&directory)?;
    let before = b"approved old-path source file";
    let after: Vec<_> = (0..98_335)
        .map(|byte| ((byte + index) % 251) as u8)
        .collect();
    fs::write(directory.join("before"), before)?;
    fs::write(directory.join("after"), &after)?;
    let root_id = random_id();
    let (approved, _consent) =
        ApprovedReadRoot::open(&root_id, &directory, nestlink_protocol::FILE_SIZE_BYTES)?;
    let mut server =
        FileReadServer::start(host.channels(), generation, FileRoots::new(vec![approved])?)?;
    let mut client = FileReadClient::attach(controller.channels(), generation)?;
    tokio::time::timeout(
        Duration::from_secs(2),
        read_file(&mut client, &root_id, "before", before),
    )
    .await??;
    tokio::try_join!(
        controller.poll(&f.sdk, &f.controller, &host_key, true),
        host.poll(&f.sdk, &f.host, &controller_key, true)
    )?;
    // Exercise the owner's scheduled real Quinn ACK probe before injecting
    // loss; merely allocating a standby is insufficient readiness evidence.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (controller_ready, host_ready) = tokio::try_join!(
        controller.poll(&f.sdk, &f.controller, &host_key, true),
        host.poll(&f.sdk, &f.host, &controller_key, true)
    )?;
    for status in [&controller_ready, &host_ready] {
        assert!(status.policy.standby_observer.is_some());
        assert!(status.policy.outstanding_work.is_none());
        assert!(status.policy.terminal.is_none());
        assert_eq!(status.policy.epoch, 1);
    }
    let standby = [
        controller
            .standby_local_addr()
            .ok_or("controller standby")?,
        host.standby_local_addr().ok_or("host standby")?,
    ];
    assert!(
        observations
            .iter()
            .all(|observation| observation.snapshot().path_epoch == Some(1))
    );
    // Start before asking the external controller to install DROP. This is a
    // conservative bound: marker dispatch/nft setup is included, never omitted.
    let started = Instant::now();
    publish(
        root,
        &format!("ready-{index:02}.json"),
        &json!({"trial": index, "active_relay": active, "standby_relay": spare,
        "business_generation": generation, "original_node_expiry_unix_ms": original_expiry}),
    )?;
    wait_marker(
        root,
        &format!("installed-{index:02}"),
        started + Duration::from_secs(2),
    )
    .await?;
    tokio::time::timeout_at(started + Duration::from_secs(3), async {
        tokio::try_join!(
            async {
                loop {
                    let status = controller
                        .poll_with_path_migration(&f.sdk, &f.controller, &host_key, true)
                        .await?;
                    assert!(status.policy.terminal.is_none());
                    if status.policy.epoch == 2 {
                        break Ok::<_, nestlink_sdk::native::SessionEstablishError>(());
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            },
            async {
                loop {
                    let status = host
                        .poll_with_path_migration(&f.sdk, &f.host, &controller_key, true)
                        .await?;
                    assert!(status.policy.terminal.is_none());
                    if status.policy.epoch == 2 {
                        break Ok::<_, nestlink_sdk::native::SessionEstablishError>(());
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        )?;
        // A fresh production FileRead request and every verified source byte
        // must cross the new path while the original relay remains DROPped.
        read_file(&mut client, &root_id, "after", &after).await
    })
    .await??;
    let elapsed_us = started.elapsed().as_micros();
    assert!(elapsed_us <= 3_000_000);
    assert_eq!(
        controller.channels().network_connection_binding()?,
        original
    );
    assert_eq!(host.channels().network_connection_binding()?, original);
    assert_eq!(
        [
            controller.channels().lease_control().current_deadline()?,
            host.channels().lease_control().current_deadline()?
        ],
        original_deadlines
    );
    for observation in &observations {
        let facts = observation.snapshot();
        assert_eq!(facts.path_epoch, Some(2));
        assert_eq!(facts.binding.route_binding, Some(routes[0]));
        assert_eq!(facts.binding.business_generation, generation);
        assert_eq!(facts.binding.transport_group, Some(group));
    }
    assert_eq!(controller.status()?.policy.pending_retirements, 0);
    assert_eq!(host.status()?.policy.pending_retirements, 0);
    drop(rebind(&addresses)?);
    client.retire()?;
    tokio::try_join!(
        controller.shutdown(StopReason::TransportLost),
        host.shutdown(StopReason::TransportLost)
    )?;
    assert_eq!(
        server.shutdown(StopReason::TransportLost).await?,
        FileShutdown::Finished
    );
    assert!(server.monitor().status().finished);
    assert!(!server.monitor().status().cleanup_timed_out);
    drop(rebind(&standby)?);
    publish(
        root,
        &format!("completed-{index:02}.json"),
        &json!({"trial": index, "elapsed_us": elapsed_us,
        "original_exporter_sha256": digest(&original), "business_generation": generation,
        "transport_group": group, "path_epoch": 2, "verified_file_bytes": after.len(),
        "original_udp_released": true, "standby_udp_released": true, "file_worker_joined": true}),
    )?;
    // Clear only after business and both carrier receipts have been observed.
    wait_marker(
        root,
        &format!("cleared-{index:02}"),
        Instant::now() + Duration::from_secs(2),
    )
    .await?;
    second.finish().await?;
    f.finish().await?;
    Ok(json!({"trial": index, "elapsed_us": elapsed_us}))
}

#[tokio::test]
#[ignore = "requires the dedicated GitHub-hosted namespace and external nft DROP controller"]
async fn automatic_original_inner_survives_real_relay_drop_within_original_authority() -> Result {
    let root = fixture()?;
    let mut trials = Vec::new();
    for index in 0..TRIALS {
        trials.push(Box::pin(trial(&root, index)).await?);
    }
    let mut durations: Vec<_> = trials
        .iter()
        .map(|trial| trial["elapsed_us"].as_u64().ok_or("missing duration"))
        .collect::<std::result::Result<_, _>>()?;
    durations.sort_unstable();
    let p95 = durations[(durations.len() * 95).div_ceil(100) - 1];
    assert!(p95 <= 3_000_000);
    publish(
        &root,
        "sdk-receipt.json",
        &json!({"trials": trials, "p95_us": p95, "threshold_us": 3_000_000,
        "automatic_sdk_poll": true, "manual_migration_request": false, "retained_original_inner": true,
        "scope": "controlled-loopback-relay-DROP-file-only", "interactive_recovery_qualified": false}),
    )?;
    Ok(())
}
