use super::{LanPolicy,denied,wall_ms,mdns::{Mdns,hex},wire::{self,Body,Envelope,Replay,UdpRequest}};
use crate::network::packet_access::OnlinePacketAccess;
use socket_pktinfo::PktInfoUdpSocket;
use nestlink_transport_quic::packet_codec::{PacketAssembler,encode_direct};
use std::{collections::{BTreeMap,VecDeque},io,net::{IpAddr,Ipv4Addr,SocketAddr,SocketAddrV4,UdpSocket},sync::Mutex,time::{Duration,Instant}};

const MAX_FLOWS:usize=64;
const FLOW_IDLE:Duration=Duration::from_secs(15);
struct Listener {rule:usize,socket:PktInfoUdpSocket}
struct LocalFlow {rule:usize,client:SocketAddr,seen:Instant,replies:PacketAssembler}
struct RemoteFlow {rule:usize,socket:UdpSocket,seen:Instant,requests:PacketAssembler,discovery:PacketAssembler}
struct Limit {since:Instant,packets:u16,bytes:u32}
impl Limit {
    fn new()->Self {Self{since:Instant::now(),packets:0,bytes:0}}
    fn admit(&mut self,policy:&LanPolicy,bytes:usize)->io::Result<()> {
        if self.since.elapsed()>=Duration::from_secs(1){*self=Self::new();}
        let bytes=u32::try_from(bytes).map_err(denied)?;
        if self.packets>=policy.packets_per_second || bytes>policy.bytes_per_second.saturating_sub(self.bytes) {
            return Err(io::Error::new(io::ErrorKind::WouldBlock,"LAN rate limit"));
        }
        self.packets+=1;self.bytes+=bytes;Ok(())
    }
}
struct State {
    listeners:Vec<Listener>,
    local:BTreeMap<u64,LocalFlow>,
    remote:BTreeMap<(String,u64),RemoteFlow>,
    next_flow:u64,
    next_sequence:u64,
    next_datagram:u64,
    replay:Replay,
    outgoing:VecDeque<Body>,
    seen_broadcast:VecDeque<([u8;32],Instant)>,
    input_limit:Limit,
    output_limit:Limit,
    mdns:Mdns,
    closed:bool,
}
/// One bounded LAN adapter, sharing the caller's original packet authority and
/// mTLS connection. No TUN or elevated raw socket is created by this adapter.
pub struct LanBridge {
    policy:LanPolicy,
    local:Ipv4Addr,
    remote:Ipv4Addr,
    business:[u8;32],
    direction:nestlink_protocol::network_datagram::Direction,
    deadline:Instant,
    state:Mutex<State>,
}
impl LanBridge {
    /// Bind only after the original one-use online start succeeds. `space_id`
    /// must be the pinned space used for that exact original start.
    pub fn bind(policy:LanPolicy,space_id:&str,access:&OnlinePacketAccess)->io::Result<Self> {
        policy.validate()?;policy.check_interface()?;
        if policy.space_id!=space_id || access.remaining_lifetime().is_zero(){return Err(denied("LAN opt-in belongs to a different or expired original packet owner"));}
        let IpAddr::V4(local)=access.local_hosts()[0] else{return Err(denied("original IPv4 assignment required"));};
        let IpAddr::V4(remote)=access.remote_hosts()[0] else{return Err(denied("original remote IPv4 assignment required"));};
        let mut listeners=Vec::new();
        for (rule,value) in policy.udp.iter().enumerate().filter(|(_,value)|value.allow_local_to_peer) {
            let socket=PktInfoUdpSocket::new(socket2::Domain::IPV4)?;
            // Exclusive receive ownership. Sharing a live game's listening port
            // with SO_REUSEPORT would arbitrarily lose requests and is refused.
            socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED,value.port).into())?;
            socket.set_nonblocking(true)?;
            listeners.push(Listener{rule,socket});
        }
        let mdns=Mdns::start(&policy,hex(&access.remote_peer().0[..6]),remote)?;
        Ok(Self {deadline:Instant::now()+access.remaining_lifetime(),business:access.business_digest(),direction:access.wire_direction(),policy,local,remote,state:Mutex::new(State{listeners,local:BTreeMap::new(),remote:BTreeMap::new(),next_flow:0,next_sequence:0,next_datagram:0,replay:Replay::default(),outgoing:VecDeque::new(),seen_broadcast:VecDeque::new(),input_limit:Limit::new(),output_limit:Limit::new(),mdns,closed:false})})
    }
    fn lock(&self)->io::Result<std::sync::MutexGuard<'_,State>> {self.state.lock().map_err(|_|denied("LAN adapter state poisoned"))}
    pub fn check_current(&self)->io::Result<()> {
        if Instant::now()>=self.deadline || self.lock()?.closed{return Err(denied("original LAN owner stopped or expired"));}
        self.policy.check_interface()
    }
    /// Return one whole IP packet to the original `admit_local`/packet codec.
    /// A bounded socket poll avoids background transport owners or queues.
    pub async fn recv(&self,buffer:&mut[u8])->io::Result<usize> {
        loop {
            self.check_current()?;
            if let Some(packet)=self.poll()? {
                if buffer.len()<packet.len(){return Err(io::ErrorKind::InvalidInput.into());}
                buffer[..packet.len()].copy_from_slice(&packet);return Ok(packet.len());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    fn poll(&self)->io::Result<Option<Vec<u8>>> {
        let mut state=self.lock()?;
        state.local.retain(|_,flow|flow.seen.elapsed()<FLOW_IDLE);
        state.remote.retain(|_,flow|flow.seen.elapsed()<FLOW_IDLE);
        state.seen_broadcast.retain(|(_,seen)|seen.elapsed()<Duration::from_millis(500));
        let mut input=vec![0_u8;65_536];
        for index in 0..state.listeners.len() {
            let listener=&state.listeners[index];
            let rule_index=listener.rule;
            let received=match listener.socket.recv(&mut input){Ok(value)=>value,Err(error) if error.kind()==io::ErrorKind::WouldBlock=>continue,Err(error)=>return Err(error)};
            let (length,info)=received;
            let rule=&self.policy.udp[rule_index];
            let prefix=self.policy.prefix()?;
            let IpAddr::V4(source)=info.addr_src.ip() else{continue;};
            let discovery=info.addr_dst==IpAddr::V4(prefix.broadcast()) || info.addr_dst==IpAddr::V4(Ipv4Addr::BROADCAST);
            if info.if_index!=u64::from(self.policy.interface_index) || info.addr_src.port()==0
                || !prefix.contains(&source) || [prefix.network(),prefix.broadcast(),self.policy.interface_address].contains(&source)
                || !discovery && info.addr_dst!=IpAddr::V4(self.policy.interface_address)
                || discovery && !rule.allow_broadcast_discovery || length==0 || length>wire::UDP_MAX
                || state.outgoing.len()>=64
            {continue;}
            if discovery {
                let mut bytes=rule.port.to_be_bytes().to_vec();bytes.extend_from_slice(&input[..length]);
                let hash=nestlink_identity::digest(&bytes);
                if state.seen_broadcast.iter().any(|(seen,_)|seen==&hash){continue;}
                if state.seen_broadcast.len()>=128{state.seen_broadcast.pop_front();}
                state.seen_broadcast.push_back((hash,Instant::now()));
            }
            let flow=if let Some((id,flow))=state.local.iter_mut().find(|(_,flow)|flow.rule==rule_index && flow.client==info.addr_src) {
                flow.seen=Instant::now();*id
            }else {
                if state.local.len()>=MAX_FLOWS{continue;}
                state.next_flow=state.next_flow.checked_add(1).ok_or_else(||denied("LAN flow sequence exhausted"))?;
                let flow=state.next_flow;
                let replies=PacketAssembler::new(wire::flow_binding(self.business,&rule.id,flow,true,false),self.direction.reverse(),wire::UDP_MAX)?;
                state.local.insert(flow,LocalFlow{rule:rule_index,client:info.addr_src,seen:Instant::now(),replies});flow
            };
            self.enqueue_udp(&mut state,false,UdpRequest{rule:rule.id.clone(),flow,payload:input[..length].to_vec(),discovery})?;
        }
        let mut replies=Vec::new();
        for ((rule_id,flow_id),flow) in &mut state.remote {
            let rule=&self.policy.udp[flow.rule];
            match flow.socket.recv_from(&mut input) {
                Ok((length,source)) if source==SocketAddr::V4(rule.local_target) && length>0 && length<=wire::UDP_MAX=>{
                    flow.seen=Instant::now();replies.push(Body::Reply(UdpRequest{rule:rule_id.clone(),flow:*flow_id,payload:input[..length].to_vec(),discovery:false}));
                },
                Ok(_)=>{},Err(error) if error.kind()==io::ErrorKind::WouldBlock=>{},Err(error)=>return Err(error),
            }
        }
        for reply in replies {if let Body::Reply(reply)=reply {self.enqueue_udp(&mut state,true,reply)?;}}
        if let Some((withdraw,service))=state.mdns.poll(&self.policy)? {
            if state.outgoing.len()<64{state.outgoing.push_back(if withdraw{Body::Withdraw(service)}else{Body::Service(service)});}
        }
        let Some(body)=state.outgoing.pop_front() else{return Ok(None);};
        state.next_sequence=state.next_sequence.checked_add(1).ok_or_else(||denied("LAN wire sequence exhausted"))?;
        let envelope=Envelope{version:1,space:self.policy.space_id.clone(),business:self.business.to_vec(),sequence:state.next_sequence,sent_ms:wall_ms()?,hops:1,body:Some(body)};
        let packet=wire::packet(self.local,self.remote,self.policy.transport_port,&envelope)?;
        match state.output_limit.admit(&self.policy,packet.len()) {Ok(())=>Ok(Some(packet)),Err(error) if error.kind()==io::ErrorKind::WouldBlock=>Ok(None),Err(error)=>Err(error)}
    }
    fn enqueue_udp(&self,state:&mut State,reply:bool,request:UdpRequest)->io::Result<()> {
        state.next_datagram=state.next_datagram.checked_add(1).ok_or_else(||denied("LAN application datagram sequence exhausted"))?;
        let binding=wire::flow_binding(self.business,&request.rule,request.flow,reply,request.discovery);
        let fragments=encode_direct(binding,self.direction,state.next_datagram,&request.payload)?;
        if state.outgoing.len()+fragments.len()>64{return Ok(());}
        for payload in fragments {
            let fragment=UdpRequest{rule:request.rule.clone(),flow:request.flow,payload,discovery:request.discovery};
            state.outgoing.push_back(if reply{Body::Reply(fragment)}else{Body::Request(fragment)});
        }
        Ok(())
    }
    /// Called only after the original authenticated peer's packet passed
    /// `OnlinePacketAccess::admit_remote`, on that same original carrier.
    pub fn receive_admitted(&self,packet:&[u8])->io::Result<usize> {
        self.check_current()?;
        let envelope=wire::parse(packet,self.remote,self.local,self.policy.transport_port)?;
        let mut state=self.lock()?;
        state.replay.admit(&envelope,&self.policy.space_id,&self.business)?;
        state.input_limit.admit(&self.policy,packet.len())?;
        match envelope.body.ok_or_else(||denied("missing LAN body"))? {
            Body::Request(request)=>{
                let index=self.policy.udp.iter().position(|rule|rule.id==request.rule && rule.allow_peer_to_local).ok_or_else(||denied("remote UDP rule or direction denied"))?;
                let rule=&self.policy.udp[index];
                if request.flow==0 || request.payload.is_empty() || request.payload.len()>wire::UDP_MAX || request.discovery && !rule.allow_broadcast_discovery {
                    return Err(denied("remote UDP request exceeds its explicit policy"));
                }
                let key=(request.rule.clone(),request.flow);
                if !state.remote.contains_key(&key) {
                    if state.remote.len()>=MAX_FLOWS{return Err(denied("remote UDP flow limit"));}
                    let socket=UdpSocket::bind((self.policy.interface_address,0))?;
                    socket.set_broadcast(rule.allow_broadcast_discovery)?;socket.set_ttl(1)?;socket.set_nonblocking(true)?;
                    let requests=PacketAssembler::new(wire::flow_binding(self.business,&request.rule,request.flow,false,false),self.direction.reverse(),wire::UDP_MAX)?;
                    let discovery=PacketAssembler::new(wire::flow_binding(self.business,&request.rule,request.flow,false,true),self.direction.reverse(),wire::UDP_MAX)?;
                    state.remote.insert(key.clone(),RemoteFlow{rule:index,socket,seen:Instant::now(),requests,discovery});
                }
                let destination=if request.discovery {SocketAddrV4::new(self.policy.prefix()?.broadcast(),rule.port)}else{rule.local_target};
                let flow=state.remote.get_mut(&key).ok_or_else(||denied("original remote UDP flow disappeared"))?;
                let assembly=if request.discovery{&mut flow.discovery}else{&mut flow.requests};
                let Some(payload)=assembly.insert(&request.payload,Instant::now())? else{return Ok(packet.len());};
                let written=flow.socket.send_to(&payload,destination)?;
                if written!=payload.len(){return Err(io::ErrorKind::WriteZero.into());}
                flow.seen=Instant::now();
            },
            Body::Reply(reply)=>{
                if reply.discovery || reply.payload.is_empty() || reply.payload.len()>wire::UDP_MAX{return Err(denied("invalid local UDP reply"));}
                let flow=state.local.get_mut(&reply.flow).filter(|flow|flow.seen.elapsed()<FLOW_IDLE && self.policy.udp[flow.rule].id==reply.rule).ok_or_else(||denied("unsolicited or stale UDP response"))?;
                let Some(payload)=flow.replies.insert(&reply.payload,Instant::now())? else{return Ok(packet.len());};
                flow.seen=Instant::now();let client=flow.client;let index=flow.rule;
                let listener=state.listeners.iter().find(|listener|listener.rule==index).ok_or_else(||denied("original local UDP listener stopped"))?;
                if listener.socket.send_to(&payload,&client.into())?!=payload.len(){return Err(io::ErrorKind::WriteZero.into());}
            },
            Body::Service(service)=>state.mdns.receive(&self.policy,false,service)?,
            Body::Withdraw(service)=>state.mdns.receive(&self.policy,true,service)?,
        }
        Ok(packet.len())
    }
    /// Close local UDP sockets immediately, then wait for DNS-SD goodbyes and
    /// the maintained daemon's socket-release receipt under one absolute cap.
    pub fn shutdown(&self,deadline:Instant)->io::Result<()> {
        let mut state=self.lock()?;state.closed=true;state.listeners.clear();state.local.clear();state.remote.clear();state.outgoing.clear();state.seen_broadcast.clear();state.mdns.shutdown(deadline)
    }
}
