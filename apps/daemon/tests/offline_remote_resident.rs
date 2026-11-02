//! Real protected login + original HTTP authority + resident CLI + native IPC.
//! Linux uses its actual Secret Service and X11 capture, Windows its original
//! DPAPI and capture owners. No fixture can inject a permit, process nonce,
//! consumed offline owner, capture frame or product data into either process.
#![cfg(any(target_os = "linux", windows))]
#[path = "offline_remote_resident/support.rs"]
mod support;
use nestlink_app_core::{
    Authentication, NativeDisplayState, NativeSessionBinding, NativeSessionCleanup,
    NativeSessionStatus, Snapshot,
};
use nestlink_app_ipc::{
    Client, NativeVideoMessage, VideoClient,
    files::{FileDirection, LocalReadRootSelection, NativeFileCommand, NativeFileReply},
    wire::{Command, ExitResult, Rejection, Reply},
};
use serde_json::json;
use std::{
    io,
    path::Path,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use support::{Fixture, Platform, Resident, Result, activate, start, wall};

fn peer() -> Result<std::net::SocketAddr> {
    let tcp = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = tcp.local_addr()?;
    let udp = std::net::UdpSocket::bind(address)?;
    drop(udp);
    drop(tcp);
    Ok(address)
}
fn binding(snapshot: &Snapshot) -> Result<NativeSessionBinding> {
    let view = snapshot
        .native_session
        .data
        .as_ref()
        .ok_or("native session missing")?;
    Ok(NativeSessionBinding {
        request_id: view.request_id.clone(),
        connection_generation: view.connection_generation,
    })
}
async fn snapshot(client: &mut Client) -> Result<Arc<Snapshot>> {
    Ok(client.request(0, Command::Snapshot).await?.snapshot)
}
async fn connected(directory: &Path) -> Result<Client> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(mut client) = Client::connect(directory).await {
                let view = snapshot(&mut client).await?;
                if view
                    .native_session
                    .data
                    .as_ref()
                    .is_some_and(|v| v.status == NativeSessionStatus::Connected)
                {
                    assert_eq!(view.authentication, Authentication::Disconnected);
                    assert!(view.server.is_none() && view.principal.is_none());
                    assert!(view.native_offline.is_some());
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(client);
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?
}
async fn displays(
    client: &mut Client,
    generation: u64,
    binding: &NativeSessionBinding,
) -> Result<NativeDisplayState> {
    match client
        .request(
            generation,
            Command::GetNativeDisplays {
                binding: binding.clone(),
            },
        )
        .await?
        .result
    {
        Reply::NativeDisplays {
            state: Some(state), ..
        } => Ok(state),
        other => Err(io::Error::other(format!(
            "display state: {}",
            serde_json::to_string(&other)?
        ))
        .into()),
    }
}
async fn approve_capture(
    host: &mut Client,
    source: &mut Client,
    directory: &Path,
) -> Result<VideoClient> {
    let host_snapshot = snapshot(host).await?;
    let generation = host_snapshot.generation;
    let scope = binding(&host_snapshot)?;
    let state = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let state = displays(host, generation, &scope).await?;
            if !state.displays.is_empty() {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    let source_id = state.displays[0].source;
    if state.local_approval_required {
        let reply = host
            .request(
                generation,
                Command::ApproveNativeDisplays {
                    binding: scope.clone(),
                    catalog: state.catalog.ok_or("candidate catalog")?,
                    sources: vec![source_id],
                    initial_source: source_id,
                },
            )
            .await?;
        assert!(matches!(
            reply.result,
            Reply::NativeDisplays { state: Some(_), .. }
        ));
    } else {
        // The original Windows/X11 View route selects its default display as
        // part of the user's original trusted View consent.
        assert!(state.approved_sources.contains(&source_id));
    }
    let source_snapshot = snapshot(source).await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let state = displays(source, source_snapshot.generation, &scope).await?;
            if state
                .selected
                .as_ref()
                .is_some_and(|selection| selection.source == source_id)
            {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    Ok(VideoClient::open(
        directory,
        source_snapshot.generation,
        scope.request_id,
        scope.connection_generation,
        source_id,
    )
    .await?)
}
async fn frame(video: &mut VideoClient) -> Result {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match video.receive().await? {
                NativeVideoMessage::Frame(frame) => {
                    assert_eq!(frame.codec, 0, "the enrolled scope contains only VP8");
                    assert!(!frame.hardware_decode);
                    assert!(frame.width > 0 && frame.height > 0);
                    assert_eq!(
                        frame.pixels.len(),
                        frame.width as usize * frame.height as usize * 4
                    );
                    #[cfg(target_os = "linux")]
                    {
                        let pixel = &frame.pixels
                            [(frame.width as usize * frame.height as usize / 2) * 4..][..4];
                        assert!(
                            pixel[1] > 200 && pixel[0] < 40 && pixel[2] < 40,
                            "actual X11 root green was not delivered: {pixel:?}"
                        );
                    }
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                }
                NativeVideoMessage::Layout(_) => {}
                NativeVideoMessage::Closed(_) => {
                    return Err("video closed before actual pixels".into());
                }
            }
        }
    })
    .await?
}
async fn files(
    client: &mut Client,
    generation: u64,
    scope: &NativeSessionBinding,
    action: NativeFileCommand,
) -> Result<NativeFileReply> {
    match client
        .request(
            generation,
            Command::NativeFiles {
                binding: scope.clone(),
                action,
            },
        )
        .await?
        .result
    {
        Reply::NativeFiles { result, .. } => Ok(result),
        other => {
            Err(io::Error::other(format!("file reply: {}", serde_json::to_string(&other)?)).into())
        }
    }
}
async fn actual_file(
    host: &mut Client,
    source: &mut Client,
    root: &Path,
    destination: &Path,
    name: &str,
) -> Result {
    let host_snapshot = snapshot(host).await?;
    let source_snapshot = snapshot(source).await?;
    let scope = binding(&source_snapshot)?;
    let reply = files(
        host,
        host_snapshot.generation,
        &scope,
        NativeFileCommand::SelectHostReadRoots {
            roots: vec![LocalReadRootSelection {
                directory: root.to_string_lossy().into_owned(),
                display_name: "Explicit resident test root".into(),
                disclose_directory: false,
            }],
        },
    )
    .await?;
    let root_id = match reply {
        NativeFileReply::HostRootsSelected { roots, .. } if roots.len() == 1 => {
            roots[0].root_id.clone()
        }
        other => {
            return Err(
                io::Error::other(format!("host root: {}", serde_json::to_string(&other)?)).into(),
            );
        }
    };
    let reply = files(
        source,
        source_snapshot.generation,
        &scope,
        NativeFileCommand::ListRoots {
            direction: FileDirection::Read,
        },
    )
    .await?;
    assert!(
        matches!(reply,NativeFileReply::Roots { roots,.. } if roots.len()==1 && roots[0].root_id==root_id)
    );
    let fresh_directory = destination.join(name);
    let reply = files(
        source,
        source_snapshot.generation,
        &scope,
        NativeFileCommand::Download {
            root_id,
            relative_path: "source.bin".into(),
            local_directory: fresh_directory.to_string_lossy().into_owned(),
            local_name: name.into(),
        },
    )
    .await?;
    let task_id = match reply {
        NativeFileReply::Task { task } => task.task_id,
        other => {
            return Err(
                io::Error::other(format!("download: {}", serde_json::to_string(&other)?)).into(),
            );
        }
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let NativeFileReply::Task { task } = files(
                source,
                source_snapshot.generation,
                &scope,
                NativeFileCommand::Task {
                    task_id: task_id.clone(),
                },
            )
            .await?
            {
                if task.finished {
                    assert_eq!(task.phase, "completed", "download error {:?}", task.error);
                    assert_eq!(task.confirmed_bytes, 262144);
                    assert!(task.error.is_none());
                    break;
                }
            } else {
                return Err::<(), Box<dyn std::error::Error + Send + Sync>>(
                    "file task disappeared".into(),
                );
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok(())
    })
    .await??;
    assert_eq!(
        std::fs::read(fresh_directory.join(name))?,
        std::fs::read(root.join("source.bin"))?
    );
    Ok(())
}

async fn stopped(client: &mut Client) -> Result<Arc<Snapshot>> {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let view = snapshot(client).await?;
            if let Some(offline) = &view.native_offline
                && matches!(
                    offline.status,
                    NativeSessionStatus::Stopped | NativeSessionStatus::Failed
                )
            {
                assert_eq!(offline.status, NativeSessionStatus::Stopped);
                assert_eq!(offline.cleanup, Some(NativeSessionCleanup::Succeeded));
                assert!(offline.failure.is_none());
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(view);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?
}

async fn data_and_rebuild(transport: &str) -> Result {
    let temporary = tempfile::tempdir()?;
    let platform = Platform::new(temporary.path()).await?;
    let mut fixture = Fixture::new(temporary.path(), &platform).await?;
    let peer = peer()?;
    let mut source = Resident::spawn(&platform, &fixture, false, transport, peer).await?;
    let mut host = Resident::spawn(&platform, &fixture, true, transport, peer).await?;
    let bundle = activate(&mut source, &mut host, &fixture).await?;
    fixture.offline().await?;
    tokio::time::sleep(Duration::from_millis(
        fixture.online_expiry.saturating_sub(wall()?) + 25,
    ))
    .await;
    assert!(wall()? >= fixture.online_expiry);
    start(&mut source, &mut host).await?;
    let mut source_ipc = connected(&fixture.source).await?;
    let mut host_ipc = connected(&fixture.host).await?;
    let old = snapshot(&mut source_ipc).await?;
    let runtime = source_ipc.runtime_id().to_owned();
    let root = temporary.path().join("explicit-host-root");
    let destination = temporary.path().join("explicit-downloads");
    std::fs::create_dir(&root)?;
    std::fs::create_dir(&destination)?;
    let bytes: Vec<u8> = (0..262144).map(|value| (value % 251) as u8).collect();
    std::fs::write(root.join("source.bin"), bytes)?;
    let mut video = approve_capture(&mut host_ipc, &mut source_ipc, &fixture.source).await?;
    frame(&mut video).await?;
    actual_file(
        &mut host_ipc,
        &mut source_ipc,
        &root,
        &destination,
        "first.bin",
    )
    .await?;
    let spent = snapshot(&mut source_ipc)
        .await?
        .native_offline
        .as_ref()
        .ok_or("budget")?
        .budget
        .remaining_bytes;
    // The peer observes the original carrier close and retains its own finite
    // authority. Only the initiator issues the explicit rebuild command.
    source.send(json!({"command":"rebuild"})).await?;
    source.event("carrier_retiring").await?;
    let source_stop = source.event("connection_stopped").await?;
    let host_stop = host.event("connection_stopped").await?;
    for receipt in [source_stop, host_stop] {
        assert_eq!(receipt["cleanup"], "succeeded");
        assert!(receipt["failure"].is_null());
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while let Ok(message) = video.receive().await {
            if matches!(message, NativeVideoMessage::Closed(_)) {
                break;
            }
        }
    })
    .await?;
    tokio::time::timeout(Duration::from_secs(3), async {
        while source_ipc
            .request(old.generation, Command::Snapshot)
            .await
            .is_ok()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    if transport == "quic" {
        drop(std::net::UdpSocket::bind(peer)?);
    } else {
        drop(tokio::net::TcpListener::bind(peer).await?);
    }
    start(&mut source, &mut host).await?;
    let mut source_ipc = connected(&fixture.source).await?;
    let mut host_ipc = connected(&fixture.host).await?;
    assert_eq!(source_ipc.runtime_id(), runtime);
    let fresh = snapshot(&mut source_ipc).await?;
    assert!(fresh.generation > old.generation);
    let offline = fresh.native_offline.as_ref().ok_or("rebuilt scope")?;
    assert_eq!(offline.bundle_id, bundle);
    assert_eq!(offline.budget.connection_attempts, 2);
    assert!(offline.budget.remaining_bytes <= spent);
    let stale = source_ipc
        .request(
            old.generation,
            Command::NativeFiles {
                binding: binding(&fresh)?,
                action: NativeFileCommand::ListRoots {
                    direction: FileDirection::Read,
                },
            },
        )
        .await?;
    assert!(matches!(
        stale.result,
        Reply::Rejected {
            reason: Rejection::StaleGeneration
        }
    ));
    let mut video = approve_capture(&mut host_ipc, &mut source_ipc, &fixture.source).await?;
    frame(&mut video).await?;
    actual_file(
        &mut host_ipc,
        &mut source_ipc,
        &root,
        &destination,
        "second.bin",
    )
    .await?;
    assert!(
        snapshot(&mut source_ipc)
            .await?
            .native_offline
            .as_ref()
            .ok_or("new cumulative budget")?
            .budget
            .remaining_bytes
            < spent - 262144
    );
    // EOF and authenticated IPC Exit both join the actual product owners and
    // remove the original socket. A fresh process cannot restore this nonce.
    if transport == "quic" {
        source.finish(true).await?;
    } else {
        let generation = snapshot(&mut source_ipc).await?.generation;
        assert!(matches!(
            source_ipc.request(generation, Command::Exit).await?.result,
            Reply::Exited {
                result: ExitResult::Complete
            }
        ));
        source.exited(true).await?;
    }
    host.finish(false).await?;
    assert!(Client::connect(&fixture.source).await.is_err());
    assert!(!fixture.source.join("daemon-endpoint.json").exists());
    if transport == "quic" {
        drop(std::net::UdpSocket::bind(peer)?);
    } else {
        drop(tokio::net::TcpListener::bind(peer).await?);
    }
    fixture.finish().await?;
    platform.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resident_quic_original_http_consume_real_pixels_files_rebuild_and_eof() -> Result {
    data_and_rebuild("quic").await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resident_tls_original_http_consume_real_pixels_files_rebuild_and_ipc_exit() -> Result {
    data_and_rebuild("tls").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn management_commands_fence_delivery_before_success_or_failed_http_and_never_rearm() -> Result
{
    let temporary = tempfile::tempdir()?;
    let platform = Platform::new(temporary.path()).await?;
    let cases = [
        (json!({"command":"policy"}), "policy", true),
        (
            json!({"command":"enable","expected_revision":1,"enabled":true}),
            "policy",
            true,
        ),
        (
            json!({"command":"enable","expected_revision":999,"enabled":true}),
            "command_failed",
            true,
        ),
        (json!({"command":"recover"}), "online_state", true),
        (
            json!({"command":"revoke","bundle_id":nestlink_auth::random_id()}),
            "command_failed",
            true,
        ),
        (
            json!({"command":"revoke","bundle_id":"this"}),
            "revoked",
            true,
        ),
        (json!({"command":"policy"}), "command_failed", false),
        (json!({"command":"recover"}), "command_failed", false),
    ];
    for (index, (mut command, event, restore)) in cases.into_iter().enumerate() {
        let area = temporary.path().join(format!("case-{index}"));
        std::fs::create_dir(&area)?;
        let mut fixture = Fixture::new(&area, &platform).await?;
        let peer = peer()?;
        let mut source = Resident::spawn(&platform, &fixture, false, "quic", peer).await?;
        let mut host = Resident::spawn(&platform, &fixture, true, "quic", peer).await?;
        let bundle = activate(&mut source, &mut host, &fixture).await?;
        if command["bundle_id"] == "this" {
            command["bundle_id"] = json!(bundle);
        }
        fixture.offline().await?;
        start(&mut source, &mut host).await?;
        let mut ipc = connected(&fixture.source).await?;
        let before = if restore {
            Some(fixture.hold_management().await?)
        } else {
            None
        };
        source.send(command).await?;
        if let Some(before) = before {
            tokio::time::timeout(Duration::from_secs(5), async {
                while fixture.requests.load(Ordering::Acquire) == before {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await?;
        }
        // No HTTP response has been released, including background polls. A
        // missing pre-request fence leaves this actual IPC session connected.
        let final_snapshot = stopped(&mut ipc).await?;
        assert!(
            final_snapshot
                .native_offline
                .as_ref()
                .ok_or("terminal authority")?
                .budget
                .stopped
        );
        fixture.gate.send_replace(false);
        source.event(event).await?;
        source
            .request(json!({"command":"start"}), "command_failed")
            .await?;
        source.finish(false).await?;
        host.finish(false).await?;
        fixture.finish().await?;
    }
    platform.shutdown().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_original_listener_eof_stop_logout_and_identity_change_join_actual_socket() -> Result
{
    let temporary = tempfile::tempdir()?;
    let platform = Platform::new(temporary.path()).await?;
    for (index, (transport, termination)) in [
        ("quic", "eof"),
        ("tls", "stop"),
        ("quic", "logout"),
        ("tls", "identity"),
    ]
    .into_iter()
    .enumerate()
    {
        let area = temporary.path().join(format!("pending-{index}"));
        std::fs::create_dir(&area)?;
        let mut fixture = Fixture::new(&area, &platform).await?;
        let peer = peer()?;
        let mut source = Resident::spawn(&platform, &fixture, false, transport, peer).await?;
        let mut host = Resident::spawn(&platform, &fixture, true, transport, peer).await?;
        activate(&mut source, &mut host, &fixture).await?;
        fixture.offline().await?;
        host.request(json!({"command":"start"}), "listening")
            .await?;
        match termination {
            "eof" => host.finish(true).await?,
            "stop" => host.finish(false).await?,
            "logout" => {
                nestlink_platform_security::replace_private_metadata(
                    &fixture.host.join("remember-login.json"),
                    b"false",
                )?;
                host.exited(false).await?;
            }
            "identity" => {
                let path = fixture.host.join("installation-device.json");
                let mut identity: serde_json::Value = serde_json::from_slice(
                    &nestlink_platform_security::read_private(&path, 1024)?,
                )?;
                identity["device_id"] = json!(nestlink_auth::random_id());
                nestlink_platform_security::replace_private_metadata(
                    &path,
                    &serde_json::to_vec(&identity)?,
                )?;
                host.exited(false).await?;
            }
            _ => unreachable!(),
        }
        source.finish(false).await?;
        assert!(Client::connect(&fixture.host).await.is_err());
        assert!(!fixture.host.join("daemon-endpoint.json").exists());
        if transport == "quic" {
            drop(std::net::UdpSocket::bind(peer)?);
        } else {
            drop(tokio::net::TcpListener::bind(peer).await?);
        }
        fixture.finish().await?;
    }
    platform.shutdown().await;
    Ok(())
}
