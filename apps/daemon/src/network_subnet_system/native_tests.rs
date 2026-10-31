//! Source-exact Actions-only kernel/carrier qualification. Online management
//! authentication and mobile/two-device acceptance keep their separate scope.
use super::*;
use base64::{Engine,engine::general_purpose::URL_SAFE_NO_PAD};
use crate::network_packet_runtime::WholePacketDevice;
use std::{process::Stdio,sync::Arc,collections::BTreeSet};
use tokio::{process::{Command,Child},io::{AsyncReadExt,AsyncWriteExt},net::{TcpListener,TcpStream,UdpSocket}};
mod fixture;
mod lab;
mod carrier;

pub(super) const ROLE_TEST:&str="network_subnet_system::native_tests::hosted_native_role";
fn lab_only()->Result {
    if std::env::var("GITHUB_ACTIONS").as_deref()!=Ok("true")||std::env::var("NESTLINK_SUBNET_NATIVE_LAB").as_deref()!=Ok("1") {return Err(io::Error::other("subnet native qualification requires its explicit isolated GitHub-hosted Linux VM opt-in").into());}Ok(())
}
async fn finished(child:&mut Child)->Result<bool> {Ok(tokio::time::timeout(Duration::from_secs(10),child.wait()).await??.success())}
async fn connect(plan:&Plan,helper:&mut Child)->Result<Arc<pipe::PacketPipe>> {
    tokio::time::timeout(Duration::from_secs(12),async {loop {
        if let Some(status)=helper.try_wait()? {return Err(io::Error::other(format!("original root subnet helper exited before handoff: {status}")).into());}
        match pipe::PacketPipe::connect(plan).await {Ok(pipe)=>return Ok(Arc::new(pipe)),Err(error) if error.downcast_ref::<io::Error>().is_some_and(|error|matches!(error.kind(),io::ErrorKind::NotFound|io::ErrorKind::ConnectionRefused))=>tokio::time::sleep(Duration::from_millis(25)).await,Err(error)=>return Err(error)}
    }}).await?
}
async fn probe(lab:&lab::Lab,index:usize,case:&str)->Result {
    let mut command=lab.command(&format!("probe{index}"))?;command.env("NESTLINK_SUBNET_NATIVE_CASE",case);
    if !tokio::time::timeout(Duration::from_secs(8),command.status()).await??.success() {return Err(io::Error::other(format!("actual subnet {case} probe failed at site {index}")).into());}Ok(())
}

#[tokio::test]
#[ignore="isolated GitHub-hosted Linux VM, ordinary UID, passwordless sudo, iproute2/nftables/arping/util-linux and explicit NESTLINK_SUBNET_NATIVE_LAB=1 required"]
async fn overlapping_lans_kernel_nat_encrypted_udp_tcp_acl_and_exact_recovery()->Result {
    lab_only()?;
    if rustix::process::geteuid().as_raw()==0 {return Err(io::Error::other("start subnet qualification as the original ordinary hosted runner UID").into());}
    for crash in [false,true] {
        let lab=lab::Lab::new()?;
        nestlink_platform_security::create_private(&lab.config(),&serde_json::to_vec(&lab)?)?;
        if !lab.status("setup").await? {return Err(io::Error::other("exact owned subnet lab setup failed").into());}
        let fixture=fixture::Fixture::new()?;
        let plans=[fixture.plan(0,lab.plan(0),lab.bridge(0)).await?,fixture.plan(1,lab.plan(1),lab.bridge(1)).await?];
        for plan in &plans {plan.save_new()?;}
        let mut helpers=[lab.command("apply0")?.spawn()?,lab.command("apply1")?.spawn()?];
        let mut services=[lab.command("service0")?.spawn()?,lab.command("service1")?.spawn()?];
        let outcome=async {
            let (first,second)=helpers.split_at_mut(1);
            let (left,right)=tokio::join!(connect(&plans[0],&mut first[0]),connect(&plans[1],&mut second[0]));
            let pipes=[left?,right?];
            for (plan,pipe) in plans.iter().zip(&pipes) {assert_eq!(kernel::namespace(&kernel::namespace_path(plan))?,Some((pipe.receipt.namespace_device,pipe.receipt.namespace_inode)),"ordinary handoff must name the actual root-owned namespace inode");}
            let (stop,receiver)=tokio::sync::watch::channel(false);
            let bridges=carrier::start(&plans,pipes.clone(),receiver).await?;
            probe(&lab,0,"udp").await?;
            probe(&lab,0,"tcp").await?;
            probe(&lab,0,"bad-port").await?;
            probe(&lab,1,"wrong-direction").await?;
            probe(&lab,0,"spoofed-source").await?;
            if !lab.status("verify-host").await? {return Err(io::Error::other("subnet gateway changed original host state").into());}
            if crash {
                if !lab.status("kill-helper0").await? {return Err(io::Error::other("original root helper SIGKILL failed").into());}
                assert!(!finished(&mut helpers[0]).await?,"SIGKILL must bypass original helper cleanup");
                tokio::time::timeout(Duration::from_secs(5),async {loop {if lab.status("recover0").await? {return Ok::<_,Box<dyn std::error::Error+Send+Sync>>(());}tokio::time::sleep(Duration::from_millis(50)).await;}}).await??;
                assert!(!plans[0].socket()?.try_exists()?,"exact journal recovery must remove the original root socket");
                assert!(kernel::namespace(&kernel::namespace_path(&plans[0]))?.is_none(),"whole owned namespace and conntrack must disappear after original helper loss");
            }
            stop.send(true)?;
            let [left,right]=bridges;
            let left=left.await?;let right=right.await?;
            if !crash {let left=left?;let right=right?;assert!(left.sent>5&&left.received>5&&right.sent>5&&right.received>5,"actual TCP and UDP must traverse both ordinary packet owners");assert_eq!(left.spent,right.spent,"both original packet owners account the same complete IP traffic");}
            drop(pipes);
            if !crash {assert!(finished(&mut helpers[0]).await?,"normal original socket EOF must cleanly release root resources");}
            assert!(finished(&mut helpers[1]).await?,"second original root helper must confirm normal cleanup");
            for plan in &plans {assert!(kernel::namespace(&kernel::namespace_path(plan))?.is_none());assert!(!plan.socket()?.try_exists()?);std::fs::remove_file(&plan.path)?;}
            // A helper restart must not reset the original kernel byte quota.
            if !crash {plans[0].save_new()?;assert!(!lab.status("reapply0").await?,"consumed original business cannot create a second kernel owner");std::fs::remove_file(&plans[0].path)?;}
            println!("Subnet native receipt: ordinary_uid={}, overlapping_original_lans=192.168.1.0/24, distinct_aliases=10.211.1.0/24,10.211.2.0/24, real_kernel_prefix_nat=true, real_encrypted_quic_whole_packets=true, udp_mtu=1280, tcp_payload=16384, wrong_port/direction/source=denied, helper_crash={crash}, exact_namespace/socket/conntrack_cleanup=true",rustix::process::geteuid().as_raw());
            Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
        }.await;
        // All actors are exact subprocess handles. On a failure, ask the
        // root-private journal owner to stop/recover only their saved identities.
        for index in 0..2 {let _=lab.status(&format!("kill-service{index}")).await;let _=finished(&mut services[index]).await;}
        if outcome.is_err() {for (index,helper) in helpers.iter_mut().enumerate() {let _=lab.status(&format!("kill-helper{index}")).await;let _=finished(helper).await;let _=lab.status(&format!("recover{index}")).await;}}
        let teardown=lab.status("teardown").await?;
        outcome?;
        if !teardown {return Err(io::Error::other("native lab teardown failed; original root recovery receipts retained").into());}
        for entry in std::fs::read_dir(&lab.ordinary)? {let path=entry?.path();if path.is_file() {std::fs::remove_file(path)?;}}
        std::fs::remove_dir(&lab.ordinary)?;
    }
    Ok(())
}

#[tokio::test]
#[ignore="internal source-exact subprocess role for the explicit hosted subnet lab"]
async fn hosted_native_role()->Result {
    lab_only()?;
    let role=std::env::var("NESTLINK_SUBNET_NATIVE_ROLE")?;
    if role=="worker" {use clap::Parser;let journal=PathBuf::from(std::env::var("NESTLINK_SUBNET_NATIVE_JOURNAL")?);let arguments=crate::Args::try_parse_from(["nestlink-daemon".into(),"network-subnet-worker".into(),"--journal".into(),journal.display().to_string()])?;let Some(crate::Command::NetworkSubnetWorker(arguments))=arguments.command else {return Err(io::Error::other("native worker CLI differs").into());};return worker::run(arguments).await;}
    require_system_admin().await?;
    let lab=lab::Lab::checked(Path::new(&std::env::var("NESTLINK_SUBNET_NATIVE_CONFIG")?))?;
    match role.as_str() {
        "setup"=>lab.setup().await,
        "verify-host"=>lab.verify_host().await,
        "teardown"=>lab.teardown().await,
        "apply0"=>lab.apply(0).await,
        "apply1"=>lab.apply(1).await,
        "reapply0"=>{std::fs::remove_file(lab.journal(0).join("lab-helper.json"))?;lab.apply(0).await},
        "kill-helper0"=>lab.kill(0,false).await,
        "kill-helper1"=>lab.kill(1,false).await,
        "kill-service0"=>lab.kill(0,true).await,
        "kill-service1"=>lab.kill(1,true).await,
        "recover0"=>helper::recover(&journal::Store::open(&lab.journal(0))?).await,
        "recover1"=>helper::recover(&journal::Store::open(&lab.journal(1))?).await,
        "service0"=>service(&lab,0).await,
        "service1"=>service(&lab,1).await,
        "probe0"=>network_probe(0).await,
        "probe1"=>network_probe(1).await,
        _=>Err(io::Error::other("unknown source-exact native subnet role").into()),
    }
}
async fn service(lab:&lab::Lab,index:usize)->Result {
    let allowed=UdpSocket::bind((fixture::TARGET,fixture::UDP)).await?;let denied=UdpSocket::bind((fixture::TARGET,fixture::DENIED)).await?;let tcp=TcpListener::bind((fixture::TARGET,fixture::TCP)).await?;
    nestlink_platform_security::create_private(&lab.root.join(format!("service{index}.json")),&serde_json::to_vec(&process_identity(std::process::id()).await?)?)?;
    let mut first=[0_u8;2048];let mut second=[0_u8;2048];let mut connections=tokio::task::JoinSet::new();let signal=crate::space_dns_system::termination();tokio::pin!(signal);
    loop {tokio::select! {biased;
        result=&mut signal=>{result?;connections.abort_all();while connections.join_next().await.is_some(){}return Ok(());},
        packet=allowed.recv_from(&mut first)=>{let (count,peer)=packet?;assert_eq!(peer.ip().to_string(),"192.168.1.254","remote LAN must see only the approved return-SNAT gateway");allowed.send_to(&first[..count],peer).await?;},
        packet=denied.recv_from(&mut second)=>{let (count,peer)=packet?;denied.send_to(&second[..count],peer).await?;},
        accepted=tcp.accept()=>{let (mut stream,peer)=accepted?;assert_eq!(peer.ip().to_string(),"192.168.1.254");connections.spawn(async move {let mut bytes=[0_u8;2048];loop {let count=stream.read(&mut bytes).await?;if count==0{break;}stream.write_all(&bytes[..count]).await?;}Ok::<_,io::Error>(())});},
        completed=connections.join_next(),if !connections.is_empty()=>{completed.ok_or_else(||io::Error::other("subnet echo task missing"))???;},
    }}
}
async fn network_probe(index:usize)->Result {
    let case=std::env::var("NESTLINK_SUBNET_NATIVE_CASE")?;let target=fixture::DESTINATIONS[1-index];
    if case=="tcp" {let mut stream=tokio::time::timeout(Duration::from_secs(3),TcpStream::connect((target,fixture::TCP))).await??;let payload=vec![81_u8;16_384];stream.write_all(&payload).await?;let mut received=vec![0_u8;payload.len()];tokio::time::timeout(Duration::from_secs(3),stream.read_exact(&mut received)).await??;assert_eq!(payload,received);stream.shutdown().await?;return Ok(());}
    let source=if case=="spoofed-source" {kernel::command("ip",&["-4","addr","add","192.168.2.42/32","dev","eth0"]).await?;"192.168.2.42"}else{fixture::TARGET};
    let socket=UdpSocket::bind((source,0)).await?;let port=if case=="bad-port" {fixture::DENIED}else{fixture::UDP};let payload=vec![73_u8;1252];socket.send_to(&payload,(target,port)).await?;let mut received=[0_u8;2048];let result=tokio::time::timeout(Duration::from_millis(if case=="udp" {3000}else{600}),socket.recv_from(&mut received)).await;
    if case=="udp" {let (count,peer)=result??;assert_eq!(peer.ip().to_string(),target);assert_eq!(peer.port(),port);assert_eq!(&received[..count],payload);}else{assert!(result.is_err(),"unauthorized source/port/direction reached a real listening LAN service");}Ok(())
}
