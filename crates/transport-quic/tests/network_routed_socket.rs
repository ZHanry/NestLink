//! Actions-only routed transport roles. No SDK signaling, business endpoint
//! proof, actual FileRead worker, TUN injection or ICE hole punching is claimed.
#![cfg(target_os = "linux")]
#[path = "network_routed_socket/authority.rs"]
mod authority;
use nestlink_identity::{InstallationIdentity, digest};
use nestlink_protocol::network::PeerId;
use nestlink_transport_quic::routed::{self, AdjacencyEndpoint, RelayForwarder};
use nestlink_transport_stream::{Channel, read_frame, write_frame};
use serde_json::json;
use std::{fs, io, net::{SocketAddr, UdpSocket}, path::{Path, PathBuf}, time::Duration};
use tokio::time::Instant;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const FIRST: &str = "10.210.1.2:45001";
const SECOND: &str = "10.210.2.2:45002";
const RELAY: [&str; 2] = ["10.211.1.1:4433", "10.211.2.1:4434"];
const MARKER: &[u8] = b"NestLink owned routed opaque payload 1280";

fn fixture(namespace: bool) -> Result<PathBuf> {
    assert_eq!(std::env::var("GITHUB_ACTIONS")?, "true");
    assert_eq!(std::env::var("RUNNER_ENVIRONMENT")?, "github-hosted");
    assert_eq!(std::env::var("GITHUB_REPOSITORY")?, "ZHanry/NestLink");
    let root = PathBuf::from(std::env::var("NESTLINK_NETWORK_FIXTURE")?).canonicalize()?;
    let temporary = PathBuf::from(std::env::var("RUNNER_TEMP")?).canonicalize()?;
    assert!(root.starts_with(&temporary) && root != temporary);
    if namespace {
        let actual = fs::read_link("/proc/self/ns/net")?;
        let runner = std::env::var("NESTLINK_NETWORK_RUNNER_NAMESPACE")?;
        assert!(runner.starts_with("net:[") && runner.ends_with(']'));
        assert_ne!(actual.to_string_lossy(), runner);
        let status = fs::read_to_string("/proc/self/status")?;
        let uid = status.lines().find(|line| line.starts_with("Uid:")).ok_or("missing uid")?;
        assert_ne!(uid.split_whitespace().nth(1), Some("0"));
        assert_ne!(uid.split_whitespace().nth(2), Some("0"));
        println!("NESTLINK_ROUTED namespace={actual:?} pid={} {uid}", std::process::id());
    }
    Ok(root)
}
fn identity(root: &Path, role: &str) -> Result<InstallationIdentity> {
    let mut seed: [u8; 32] = fs::read(root.join(format!("{role}.seed")))?.try_into().map_err(|_| "invalid seed")?;
    Ok(InstallationIdentity::from_seed_zeroizing(&mut seed))
}
fn peer(root: &Path, role: &str) -> Result<PeerId> {
    Ok(PeerId(digest(&fs::read(root.join(format!("{role}.public")))?)))
}
fn mark(root: &Path, name: &str) -> Result {
    fs::write(root.join(format!("{name}.pending")), b"observed\n")?;
    fs::rename(root.join(format!("{name}.pending")), root.join(name))?;
    println!("NESTLINK_ROUTED event={name}");
    Ok(())
}
async fn wait_mark(root: &Path, name: &str, deadline: Instant) -> Result {
    tokio::time::timeout_at(deadline, async {
        while !root.join(name).is_file() { tokio::time::sleep(Duration::from_millis(10)).await; }
    }).await?;
    assert_eq!(fs::read(root.join(name))?, b"observed\n");
    Ok(())
}
async fn rebind(address: SocketAddr) -> Result {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match UdpSocket::bind(address) {
                Ok(socket) => { drop(socket); return Ok::<_, io::Error>(()); }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(error) => return Err(error),
            }
        }
    }).await??;
    Ok(())
}
fn receipt(root: &Path, role: &str, facts: serde_json::Value) -> Result {
    fs::write(root.join(format!("{role}-receipt.json")), serde_json::to_vec_pretty(&facts)?)?;
    Ok(())
}
fn ipv6(reverse: bool) -> Vec<u8> {
    let mut packet = vec![0; 1280];
    packet[0] = 0x60; packet[4..6].copy_from_slice(&1240u16.to_be_bytes()); packet[6] = 59; packet[7] = 64;
    packet[8] = 0xfd; packet[23] = if reverse { 2 } else { 1 };
    packet[24] = 0xfd; packet[39] = if reverse { 1 } else { 2 };
    packet[40..40 + MARKER.len()].copy_from_slice(MARKER);
    packet[1279] = u8::from(reverse);
    packet
}
#[test]
#[ignore = "GitHub-hosted network namespace orchestrator only"]
fn prepare_fixture() -> Result { authority::prepare(&fixture(false)?) }

#[tokio::test]
#[ignore = "GitHub-hosted network namespace orchestrator only"]
async fn relay_process() -> Result {
    let root = fixture(true)?;
    let case = std::env::var("NESTLINK_NETWORK_CASE")?;
    let local = identity(&root, "relay")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let first = AdjacencyEndpoint::bind(RELAY[0].parse()?, &local, peer(&root, "first")?)?;
    let second = AdjacencyEndpoint::bind(RELAY[1].parse()?, &local, peer(&root, "second")?)?;
    mark(&root, "relay-ready")?;
    let (first, second) = tokio::join!(first.accept(deadline), second.accept(deadline));
    if case == "blackhole" {
        assert!(first.is_err());
        if let Ok(mut second) = second { second.close_and_wait(Instant::now() + Duration::from_secs(5)).await?; }
        for address in RELAY { rebind(address.parse()?).await?; }
        mark(&root, "relay-rejected")?;
        receipt(&root, "relay", json!({"role":"relay","passed":true,"preauthorization_rejected":true,
            "released_udp_sockets":2,"rebound_udp_addresses":RELAY}))?;
        return Ok(());
    }
    let grants = authority::Authority::load(&root)?;
    let (authorization, stop) = grants.authorize()?;
    let mut relay = RelayForwarder::new(authorization, first?, second?)?;
    mark(&root, "relay-forwarding")?;
    let stopped = {
        let run = relay.run(); tokio::pin!(run);
        tokio::select! {
            result = &mut run => result.is_err(),
            result = wait_mark(&root, "stop-all", Instant::now() + Duration::from_secs(12)) => {
                result?; stop.revoke(); run.await.is_err()
            }
        }
    };
    assert!(stopped);
    let forwarded = relay.forwarded_fragments();
    let charged = relay.charged_bytes();
    assert!(forwarded >= 6 && charged >= 131_072);
    relay.close_and_wait(Instant::now() + Duration::from_secs(5)).await?;
    for address in RELAY { rebind(address.parse()?).await?; }
    receipt(&root, "relay", json!({"role":"relay","passed":true,"forwarded_fragments":forwarded,
        "charged_bytes":charged,"explicit_close_completed":true,"released_udp_sockets":2,"rebound_udp_addresses":RELAY}))?;
    mark(&root, "relay-finished")
}

async fn endpoint(role: &str) -> Result {
    let root = fixture(true)?;
    let case = std::env::var("NESTLINK_NETWORK_CASE")?;
    let first = role == "first";
    let address: SocketAddr = (if first { FIRST } else { SECOND }).parse()?;
    let relay: SocketAddr = RELAY[usize::from(!first)].parse()?;
    let local = identity(&root, role)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let physical = AdjacencyEndpoint::bind(address, &local, peer(&root, "relay")?)?;
    assert_eq!(physical.local_addr()?, address);
    let adjacency = physical.connect(relay, deadline).await;
    if case == "blackhole" && first {
        assert!(adjacency.is_err());
        rebind(address).await?;
        receipt(&root, role, json!({"role":role,"passed":true,"preauthorization_rejected":true,
            "released_udp_sockets":1,"rebound_udp_addresses":[address.to_string()]}))?;
        return mark(&root, "first-rejected");
    }
    let grants = authority::Authority::load(&root)?;
    let (authorization, stop) = grants.authorize()?;
    let routed = routed::establish(authorization, adjacency?, &local, deadline).await;
    if case == "blackhole" {
        assert!(routed.is_err());
        rebind(address).await?;
        receipt(&root, role, json!({"role":role,"passed":true,"inner_setup_rejected":true,
            "released_udp_sockets":1,"rebound_udp_addresses":[address.to_string()]}))?;
        return mark(&root, "second-rejected");
    }
    let mut routed = routed?;
    mark(&root, &format!("{role}-established"))?;
    let business = Instant::now() + Duration::from_secs(7);
    let payload = fs::read(root.join("payload.bin"))?;
    assert_eq!(payload.len(), 65_536);
    // Test raw routed transport only. This has no SessionPermit endpoint proof
    // and must never be reported as a FileRead business operation.
    {
        let connection = routed.connection()?;
        assert!(connection.max_datagram_size().is_some_and(|size| size >= 1280));
        if first {
            connection.send_datagram(ipv6(false).into())?;
            assert_eq!(tokio::time::timeout_at(business, connection.read_datagram()).await??.as_ref(), ipv6(true));
        } else {
            assert_eq!(tokio::time::timeout_at(business, connection.read_datagram()).await??.as_ref(), ipv6(false));
            connection.send_datagram(ipv6(true).into())?;
        }
        let (mut send, mut receive) = if first { connection.open_bi().await? } else {
            tokio::time::timeout_at(business, connection.accept_bi()).await??
        };
        if first {
            for chunk in payload.chunks(8192) { write_frame(&mut send, Channel::Control, chunk).await?; }
            let ack = tokio::time::timeout_at(business, read_frame(&mut receive)).await??;
            assert_eq!(ack.channel, Channel::Control); assert_eq!(ack.payload, digest(&payload));
            let mut reverse = Vec::new();
            for _ in 0..8 {
                let frame = tokio::time::timeout_at(business, read_frame(&mut receive)).await??;
                assert_eq!(frame.channel, Channel::Control); assert_eq!(frame.payload.len(), 8192);
                reverse.extend_from_slice(&frame.payload);
            }
            assert_eq!(reverse, payload.iter().rev().copied().collect::<Vec<_>>());
            write_frame(&mut send, Channel::Control, &digest(&reverse)).await?;
        } else {
            let mut received = Vec::new();
            for _ in 0..8 {
                let frame = tokio::time::timeout_at(business, read_frame(&mut receive)).await??;
                assert_eq!(frame.channel, Channel::Control); assert_eq!(frame.payload.len(), 8192);
                received.extend_from_slice(&frame.payload);
            }
            assert_eq!(received, payload);
            write_frame(&mut send, Channel::Control, &digest(&received)).await?;
            let reverse = payload.iter().rev().copied().collect::<Vec<_>>();
            for chunk in reverse.chunks(8192) { write_frame(&mut send, Channel::Control, chunk).await?; }
            let ack = tokio::time::timeout_at(business, read_frame(&mut receive)).await??;
            assert_eq!(ack.channel, Channel::Control); assert_eq!(ack.payload, digest(&reverse));
        }
        mark(&root, &format!("{role}-payload-verified"))?;
        if case == "cancel" {
            if first {
                write_frame(&mut send, Channel::Control, b"next bounded transport response").await?;
                wait_mark(&root, "fault-installed", business).await?;
                let read = read_frame(&mut receive); tokio::pin!(read);
                assert!(tokio::time::timeout(Duration::from_millis(150), &mut read).await.is_err());
                mark(&root, "first-read-blocked")?;
                wait_mark(&root, "stop-all", business).await?;
                stop.revoke(); routed.request_close();
                assert!(tokio::time::timeout(Duration::from_millis(500), &mut read).await?.is_err());
                mark(&root, "first-read-cancelled")?;
            } else {
                let request = tokio::time::timeout_at(business, read_frame(&mut receive)).await??;
                assert_eq!(request.payload, b"next bounded transport response");
                mark(&root, "second-request-received")?;
                wait_mark(&root, "fault-installed", business).await?;
                write_frame(&mut send, Channel::Control, &[83; 512]).await?;
                mark(&root, "second-response-sent")?;
                wait_mark(&root, "stop-all", business).await?;
            }
        } else { wait_mark(&root, "stop-all", business).await?; }
    }
    stop.revoke();
    routed.close_and_wait(Instant::now() + Duration::from_secs(5)).await?;
    rebind(address).await?;
    receipt(&root, role, json!({"role":role,"passed":true,"ipv6_packet_bytes":1280,"framed_transport_bytes_per_direction":payload.len(),
        "business_proof_exercised":false,"explicit_close_completed":true,"released_udp_sockets":1,"rebound_udp_addresses":[address.to_string()],
        "pending_read_cancelled":case == "cancel" && first}))?;
    mark(&root, &format!("{role}-finished"))
}
#[tokio::test]
#[ignore = "GitHub-hosted network namespace orchestrator only"]
async fn first_process() -> Result { endpoint("first").await }
#[tokio::test]
#[ignore = "GitHub-hosted network namespace orchestrator only"]
async fn second_process() -> Result { endpoint("second").await }
