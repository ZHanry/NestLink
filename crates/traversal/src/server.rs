use crate::stun;
use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::watch};

pub async fn serve(socket: UdpSocket, mut stop: watch::Receiver<bool>) -> io::Result<()> {
    let mut bytes = [0; stun::MAXIMUM + 1];
    let mut ips: HashMap<IpAddr, u32> = HashMap::new();
    let mut start = Instant::now();
    let mut total = 0_u32;
    loop {
        let (size, source) = tokio::select! {
            packet=socket.recv_from(&mut bytes)=>packet?,
            event=stop.changed()=>{if event.is_err()||*stop.borrow(){return Ok(());}else{continue;}}
        };
        if start.elapsed() >= Duration::from_secs(1) {
            start = Instant::now();
            ips.clear();
            total = 0;
        }
        if total >= 1000 || size > stun::MAXIMUM {
            continue;
        }
        total += 1;
        if !ips.contains_key(&source.ip()) && ips.len() >= 1024 {
            continue;
        }
        let count = ips.entry(source.ip()).or_default();
        *count += 1;
        if *count > 10 {
            continue;
        }
        let Ok(reply) = stun::response(&bytes[..size], source) else {
            continue;
        };
        socket.send_to(&reply, source).await?;
    }
}
