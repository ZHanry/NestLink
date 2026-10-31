use super::*;
use std::os::unix::fs::MetadataExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

#[derive(clap::Args)]
pub(crate) struct SubnetWorkerArgs {
    #[arg(long)]
    journal: PathBuf,
}
pub(crate) async fn run(args: SubnetWorkerArgs) -> Result {
    require_system_admin().await?;
    let journal = journal::Store::read_path(&args.journal)?;
    let plan = &journal.plan;
    plan.checked(true)?;
    let current = std::fs::metadata("/proc/self/ns/net")?;
    let original = std::fs::metadata(format!("/proc/{}/ns/net", plan.process.pid()))?;
    if current.dev() == original.dev() && current.ino() == original.ino() {
        return Err(
            io::Error::other("subnet worker must start inside a fresh isolated namespace").into(),
        );
    }
    let namespace = journal::Namespace {
        device: current.dev(),
        inode: current.ino(),
        worker: process_identity(std::process::id()).await?,
    };
    // Tokio's generic stdin uses an uncancellable blocking read. Owning the
    // real anonymous control pipe as an async Unix receiver lets normal owner
    // EOF terminate this worker without a runtime-shutdown deadlock.
    let control = rustix::io::dup(std::io::stdin())?;
    rustix::fs::fcntl_setfl(&control, rustix::fs::OFlags::NONBLOCK)?;
    let mut input = tokio::net::unix::pipe::Receiver::from_owned_fd(control)?;
    let mut output = tokio::io::stdout();
    output.write_all(pipe::CONTROL_MAGIC).await?;
    output.flush().await?;
    pipe::frame(&mut output, &serde_json::to_vec(&namespace)?).await?;
    if tokio::time::timeout(Duration::from_secs(3), input.read_u8()).await?? != 0xa5 {
        return Err(io::Error::other(
            "subnet namespace was not durably admitted by its original root helper",
        )
        .into());
    }
    let durable = journal::Store::read_path(&args.journal)?;
    let expected = durable
        .namespace
        .as_ref()
        .ok_or_else(|| io::Error::other("original namespace identity was not committed"))?;
    if expected.device != namespace.device
        || expected.inode != namespace.inode
        || expected.worker != namespace.worker
        || durable.plan.digest()? != plan.digest()?
    {
        return Err(
            io::Error::other("subnet namespace journal changed before configuration").into(),
        );
    }
    // The stable portal key crosses only the original anonymous root control
    // pipe. It is never serialized into the public plan or recovery journal.
    let server_secret = if plan.wireguard.is_some() {
        let mut bytes = zeroize::Zeroizing::new([0_u8; 32]);
        tokio::time::timeout(Duration::from_secs(1), input.read_exact(&mut *bytes)).await??;
        Some(bytes)
    } else {
        None
    };
    let device = tun_rs::DeviceBuilder::new()
        .name(plan.tun())
        .enable(false)
        .build_async()?;
    kernel::command(
        "ip",
        &[
            "link",
            "set",
            "dev",
            &plan.tun(),
            "multicast",
            "off",
            "addrgenmode",
            "none",
        ],
    )
    .await?;
    let journal_dir = args
        .journal
        .parent()
        .ok_or_else(|| io::Error::other("subnet journal parent missing"))?;
    let mut receipt =
        kernel::configure(plan, journal_dir, &device, server_secret.as_deref()).await?;
    drop(server_secret);
    let parent = pipe::SocketDirectory::open(plan)?;
    if parent.device != std::fs::metadata(journal_dir)?.dev() {
        return Err(io::Error::other(
            "subnet socket handoff requires the original root journal filesystem",
        )
        .into());
    }
    let staging = journal_dir.join("network-subnet-packet.sock");
    // Set creation permissions before bind. Never chmod/chown a pathname in
    // the ordinary owner's directory after it can be replaced with a symlink.
    let previous = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o155));
    let bound = UnixListener::bind(&staging);
    rustix::process::umask(previous);
    let listener = bound?;
    let socket = pipe::socket_metadata(&staging)?
        .ok_or_else(|| io::Error::other("new root packet socket missing"))?;
    receipt.socket_device = socket.dev();
    receipt.socket_inode = socket.ino();
    receipt.socket_parent_device = parent.device;
    receipt.socket_parent_inode = parent.inode;
    pipe::frame(&mut output, &serde_json::to_vec(&receipt)?).await?;
    if tokio::time::timeout(Duration::from_secs(3), input.read_u8()).await?? != 0x5a {
        return Err(io::Error::other(
            "subnet kernel receipt was not committed before packet handoff",
        )
        .into());
    }
    let committed = journal::Store::read_path(&args.journal)?;
    if committed.receipt.as_ref() != Some(&receipt) {
        return Err(
            io::Error::other("subnet socket was not durably recorded before exposure").into(),
        );
    }
    // Atomic rename exposes only the already journaled root socket. Retain the
    // destination directory descriptor through both handoff and exact cleanup.
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &staging,
        rustix::fs::CWD,
        &parent.path,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    std::fs::File::open(journal_dir)?.sync_all()?;
    parent.sync()?;
    let result = serve(plan, &receipt, &device, &listener, &mut input).await;
    drop(listener);
    drop(device);
    pipe::remove_socket(&parent.path, Some(&receipt))?;
    parent.sync()?;
    result
}
async fn serve(
    plan: &Plan,
    receipt: &Receipt,
    device: &tun_rs::AsyncDevice,
    listener: &UnixListener,
    input: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result {
    let wall = system_wall_ms()?;
    let remaining = plan
        .expires_at_ms
        .checked_sub(wall)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| io::Error::other("original subnet deadline expired before handoff"))?;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(remaining);
    let mut end = [0_u8; 1];
    let stream = loop {
        let accepted = tokio::select! {biased;
            _=tokio::time::sleep_until(deadline)=>return Err(io::Error::other("original subnet deadline expired before packet handoff").into()),
            _=input.read(&mut end)=>return Err(io::Error::other("original root subnet helper ended").into()),
            accepted=listener.accept()=>accepted?,
        };
        let peer = accepted.0.peer_cred()?;
        if peer.uid() != plan.uid || peer.pid() != i32::try_from(plan.process.pid()).ok() {
            drop(accepted);
            continue;
        }
        if process_identity(plan.process.pid()).await? != plan.process
            || !crate::space_dns_system::current_image_matches(&plan.process)?
        {
            return Err(io::Error::other("original ordinary subnet owner changed").into());
        }
        break accepted.0;
    };
    let (reader, mut writer) = stream.into_split();
    let mut reader = pipe::Reader::new(reader);
    pipe::frame(&mut writer, &serde_json::to_vec(receipt)?).await?;
    let mut sequence = 1_u64;
    let mut acknowledged = 0_u64;
    let mut observation_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut challenges = std::collections::VecDeque::from([(sequence, observation_deadline)]);
    tokio::time::timeout(
        Duration::from_millis(250),
        pipe::frame(&mut writer, &pipe::challenge_frame(sequence)),
    )
    .await??;
    let expected = tokio::time::timeout_at(
        deadline
            .min(observation_deadline)
            .min(tokio::time::Instant::now() + Duration::from_secs(2)),
        configuration(plan),
    )
    .await??;
    let mut buffer = vec![0_u8; 65_536];
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut observed = tokio::time::Instant::now();
    let signal = crate::space_dns_system::termination();
    tokio::pin!(signal);
    loop {
        tokio::select! {biased;
            result=&mut signal=>return result.map_err(Into::into),
            _=tokio::time::sleep_until(deadline)=>return Ok(()),
            _=tokio::time::sleep_until(observation_deadline)=>return Err(io::Error::other("original online subnet owner stopped acknowledging fresh root observation challenges").into()),
            _=input.read(&mut end)=>return Err(io::Error::other("original root subnet helper ended").into()),
            _=tick.tick()=>{
                plan.checked(true)?;
                if Plan::read(&plan.path)?.digest()?!=plan.digest()?||process_identity(plan.process.pid()).await?!=plan.process {return Err(io::Error::other("original subnet owner intent or process changed").into());}
                if observed.elapsed()>=Duration::from_secs(1) {
                    sequence=sequence.checked_add(1).ok_or_else(||io::Error::other("subnet observation challenge exhausted"))?;
                    let now=tokio::time::Instant::now();challenges.retain(|(_,expires)|*expires>now);challenges.push_back((sequence,now+Duration::from_secs(5)));
                    if challenges.len()>8 {return Err(io::Error::other("subnet observation challenge queue exceeded its fixed bound").into());}
                    tokio::time::timeout_at(deadline.min(observation_deadline).min(now+Duration::from_millis(250)),pipe::frame(&mut writer,&pipe::challenge_frame(sequence))).await??;
                    if tokio::time::timeout_at(deadline.min(observation_deadline).min(tokio::time::Instant::now()+Duration::from_secs(2)),configuration(plan)).await??!=expected {return Err(io::Error::other("exact owned subnet kernel configuration changed").into());}observed=tokio::time::Instant::now();
                }
            },
            packet=reader.frame()=>{
                let packet=match packet {Ok(packet)=>packet,Err(error) if error.kind()==io::ErrorKind::UnexpectedEof=>return Ok(()),Err(error)=>return Err(error.into())};
                if let Some(value)=pipe::challenge(&packet)? {
                    let expires=challenges.iter().find(|(issued,_)|*issued==value).map(|(_,expires)|*expires).ok_or_else(||io::Error::other("subnet observation acknowledgement was never issued by this root owner"))?;
                    if expires<=tokio::time::Instant::now()||value<acknowledged {return Err(io::Error::other("stale or replayed subnet observation acknowledgement").into());}
                    acknowledged=value;observation_deadline=expires;continue;
                }
                if packet.len()>nestlink_sdk::network::packet_access::PACKET_MTU {return Err(io::Error::other("root subnet provider refuses oversized IP injection").into());}
                let written=tokio::time::timeout_at(deadline.min(observation_deadline).min(tokio::time::Instant::now()+Duration::from_millis(250)),device.send(&packet)).await??;
                if written!=packet.len() {return Err(io::Error::other("root subnet provider requires complete IP injection").into());}
            },
            count=device.recv(&mut buffer)=>{
                let count=count?;
                if count==0||count>nestlink_sdk::network::packet_access::PACKET_MTU {return Err(io::Error::other("root subnet provider received an incomplete or oversized kernel packet").into());}
                tokio::time::timeout_at(deadline.min(observation_deadline).min(tokio::time::Instant::now()+Duration::from_millis(250)),pipe::frame(&mut writer,&buffer[..count])).await??;
            },
        }
    }
}
async fn configuration(plan: &Plan) -> Result<serde_json::Value> {
    let tun = kernel::local_link(&plan.tun()).await?;
    let lan = kernel::local_link(&plan.macvlan()).await?;
    for link in [&tun, &lan] {
        if link["ifalias"].as_str() != Some(plan.marker().as_str()) {
            return Err(io::Error::other("subnet interface owner marker changed").into());
        }
    }
    let mut firewall: serde_json::Value =
        serde_json::from_slice(&kernel::command("nft", &["-j", "list", "ruleset"]).await?)?;
    normalize(&mut firewall);
    let wireguard = if let Some(ingress) = &plan.wireguard {
        Some(ingress.configuration(plan).await?)
    } else {
        None
    };
    Ok(
        serde_json::json!({"tun":tun,"lan":lan,"wireguard":wireguard,"addresses":kernel::ip(&["-j","addr","show"]).await?,"routes":kernel::ip(&["-j","-4","route","show","table","all"]).await?,"firewall":firewall}),
    )
}
fn normalize(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                normalize(value);
            }
        }
        serde_json::Value::Object(values) => {
            values.remove("used");
            for value in values.values_mut() {
                normalize(value);
            }
        }
        _ => {}
    }
}
