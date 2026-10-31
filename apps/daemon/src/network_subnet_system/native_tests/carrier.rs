//! The real encrypted carrier and the production whole-IP admission owner.
//! This lab supplies fixed signed authority rather than pretending to log in.
use super::*;
use nestlink_identity::network::verify_network_grant;
use nestlink_platform_network::path::{NetworkPathManager, RoutePolicy};
use nestlink_protocol::network::PeerId;
use nestlink_protocol::network_datagram::Direction;
use nestlink_transport_quic::packet_codec::{DirectPacketEndpoint, PacketAssembler, encode_direct};
#[derive(Debug)]
pub(super) struct Counts {
    pub sent: u64,
    pub received: u64,
    pub spent: u64,
}
pub(super) async fn start(
    plans: &[Plan; 2],
    pipes: [Arc<pipe::PacketPipe>; 2],
    stop: tokio::sync::watch::Receiver<bool>,
) -> Result<[tokio::task::JoinHandle<Result<Counts>>; 2]> {
    start_after(plans,pipes,stop,Duration::ZERO).await
}
pub(super) async fn start_after(
    plans: &[Plan; 2],
    pipes: [Arc<pipe::PacketPipe>; 2],
    stop: tokio::sync::watch::Receiver<bool>,
    peer_delay:Duration,
) -> Result<[tokio::task::JoinHandle<Result<Counts>>; 2]> {
    let interface = NetworkPathManager::interfaces()?
        .into_iter()
        .find(|interface| {
            interface.up
                && interface
                    .addresses
                    .iter()
                    .any(|address| address.is_ipv4() && !address.is_loopback())
        })
        .ok_or_else(|| {
            io::Error::other("hosted subnet lab needs an original active IPv4 carrier interface")
        })?;
    let source = interface
        .addresses
        .iter()
        .copied()
        .find(|address| address.is_ipv4() && !address.is_loopback())
        .ok_or_else(|| io::Error::other("original carrier source disappeared"))?;
    let path = NetworkPathManager::new(RoutePolicy::Interface(interface.index))?;
    let mut first = DirectPacketEndpoint::bind(
        (source, 0).into(),
        &fixture::identity(0),
        PeerId::from_public_key(&plans[1].local_public),
        path.clone(),
    )?;
    let mut second = DirectPacketEndpoint::bind(
        (source, 0).into(),
        &fixture::identity(1),
        PeerId::from_public_key(&plans[0].local_public),
        path,
    )?;
    let revoked = BTreeSet::new();
    let context = fixture::context(&plans[0], &revoked)?;
    let signed_path =
        nestlink_sdk::network_management::decode_network_grant(&plans[0].credentials.path)?;
    let group = verify_network_grant(&signed_path, &context)?
        .claims()
        .unverified_transport_group_digest()?;
    let remote = second.local_addr();
    let started=tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(10);
    let (left, right) = tokio::join!(
        prove(&plans[0],&pipes[0],first.establish(Some(remote),plans[0].approved_access,group,deadline)),
        prove(&plans[1],&pipes[1],async {tokio::time::sleep(peer_delay).await;second.establish(None,plans[0].approved_access,group,deadline).await})
    );
    let discarded=left?;
    right?;
    if !peer_delay.is_zero() {
        assert!(started.elapsed()>=peer_delay,"actual peer proof must stay pending beyond the root challenge's initial five seconds");
        assert!(discarded>0,"a real original LAN packet must be consumed and discarded before peer proof, without replay or a business queue");
        println!("Subnet delayed peer proof receipt: delay_seconds={}, original_handshake_limit_seconds=10, unproved_lan_packets_discarded={discarded}, fresh_root_challenges_consumed=true",peer_delay.as_secs());
    }
    let [left, right] = pipes;
    let [first_plan, second_plan] = plans.clone();
    Ok([
        tokio::spawn(run(first_plan, left, first, stop.clone())),
        tokio::spawn(run(second_plan, right, second, stop)),
    ])
}
async fn prove<F>(plan:&Plan,pipe:&pipe::PacketPipe,proof:F)->Result<u64>
where F:std::future::Future<Output=Result> {
    let mut policy=fixture::policy(plan)?;
    let observed=async {
        tokio::pin!(proof);
        let mut tick=tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {tokio::select! {biased;
            _=tick.tick()=>{let revoked=BTreeSet::new();let context=fixture::context(plan,&revoked)?;let [source,destination]=fixture::authorities(plan)?;policy.refresh_addresses(&context,source,destination)?;tokio::time::timeout(Duration::from_millis(250),pipe.heartbeat()).await??;},
            result=&mut proof=>return result,
        }}
    };
    let result=pipe.during_peer_proof(observed).await;
    policy.stop();
    result
}
async fn run(
    plan: Plan,
    pipe: Arc<pipe::PacketPipe>,
    mut endpoint: DirectPacketEndpoint,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<Counts> {
    let mut policy = fixture::policy(&plan)?;
    let remote = policy.remote_peer();
    let local = policy.local_peer();
    let direction = if local < remote {
        Direction::FirstToSecond
    } else {
        Direction::SecondToFirst
    };
    let mut assembler = PacketAssembler::new(plan.approved_access, direction.reverse(), 1280)?;
    let connection = endpoint.connection()?.clone();
    let mut counts = Counts {
        sent: 0,
        received: 0,
        spent: 0,
    };
    let mut sequence = 0_u64;
    let mut buffer = vec![0_u8; 65_536];
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let outcome=async {loop {tokio::select! {biased;
        result=stop.changed()=>{result?;if *stop.borrow(){return Ok::<_,Box<dyn std::error::Error+Send+Sync>>(());}},
        _=tick.tick()=>{let revoked=BTreeSet::new();let context=fixture::context(&plan,&revoked)?;let [source,destination]=fixture::authorities(&plan)?;policy.refresh_addresses(&context,source,destination)?;tokio::time::timeout(Duration::from_millis(250),pipe.heartbeat()).await??;},
        frame=connection.read_datagram()=>{let frame=frame?;if let Some(packet)=assembler.insert(&frame,std::time::Instant::now())? {let revoked=BTreeSet::new();let context=fixture::context(&plan,&revoked)?;assert!(policy.admit_remote(&context,PeerId([99;32]),&packet).is_err(),"a wrong authenticated peer must never inject");policy.admit_remote(&context,remote,&packet)?;assert_eq!(pipe.send(&packet).await?,packet.len());counts.received+=1;}},
        packet=pipe.recv(&mut buffer)=>{let length=packet?;let packet=&buffer[..length];let revoked=BTreeSet::new();let context=fixture::context(&plan,&revoked)?;policy.admit_local(&context,packet)?;sequence=sequence.checked_add(1).ok_or_else(||io::Error::other("native carrier sequence exhausted"))?;for frame in encode_direct(plan.approved_access,direction,sequence,packet)? {connection.send_datagram(frame.into())?;}counts.sent+=1;},
    }}}.await;
    counts.spent = policy.spent_bytes();
    policy.stop();
    let shutdown = pipe.shutdown().await;
    let side=if plan.local_public==fixture::identity(0).public_key(){"first_client"}else{"second_server"};
    let closing_rtt=connection.rtt();
    drop(connection);
    let close_started=tokio::time::Instant::now();
    println!("Subnet native physical close: side={side}, rtt_ms={}, cleanup_budget_ms=5000",closing_rtt.as_millis());
    let close = endpoint
        .close_and_wait(close_started + Duration::from_secs(5))
        .await;
    println!("Subnet native physical close result: side={side}, elapsed_ms={}, result={close:?}",close_started.elapsed().as_millis());
    outcome?;
    shutdown?;
    close.map_err(|error|io::Error::new(error.kind(),format!("{side} original QUIC physical socket release failed after {}ms with last RTT {}ms: {error}",close_started.elapsed().as_millis(),closing_rtt.as_millis())))?;
    Ok(counts)
}
