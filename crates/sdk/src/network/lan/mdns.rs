//! The maintained component owns DNS records, probing, cache and multicast.
//! This adapter forwards selected service descriptions, never raw multicast.
use super::{LanPolicy, denied, policy::name, wire::{Service,Txt,MAX_RECORDS}};
use mdns_sd::{DaemonStatus,IfKind,Receiver,ServiceDaemon,ServiceEvent,ServiceInfo,TxtProperty,UnregisterStatus};
use std::{collections::{BTreeMap,VecDeque},io,net::Ipv4Addr,time::{Duration,Instant}};

pub(super) struct Mdns {
    daemon:Option<ServiceDaemon>,
    browsers:Vec<(String,Receiver<ServiceEvent>)>,
    local:BTreeMap<String,Service>,
    remote:BTreeMap<(String,String),(String,Service,Instant)>,
    pending:Vec<Receiver<UnregisterStatus>>,
    output:VecDeque<(bool,Service)>,
    last_refresh:Instant,
    peer_tag:String,
    peer_address:Ipv4Addr,
}
impl Mdns {
    pub(super) fn start(policy:&LanPolicy,peer_tag:String,peer_address:Ipv4Addr)->io::Result<Self> {
        let daemon=if policy.mdns.is_empty(){None}else{Some(ServiceDaemon::new().map_err(denied)?)};
        let mut state=Self {daemon,browsers:Vec::new(),local:BTreeMap::new(),remote:BTreeMap::new(),pending:Vec::new(),output:VecDeque::new(),last_refresh:Instant::now(),peer_tag,peer_address};
        if let Some(daemon)=&state.daemon {
            daemon.disable_interface(IfKind::All).map_err(denied)?;
            daemon.enable_interface(IfKind::IndexV4(policy.interface_index)).map_err(denied)?;
            for rule in policy.mdns.iter().filter(|rule|rule.allow_export) {
                if !state.browsers.iter().any(|(kind,_)|kind==&rule.service_type) {
                    state.browsers.push((rule.service_type.clone(),daemon.browse(&rule.service_type).map_err(denied)?));
                }
            }
        }
        Ok(state)
    }
    pub(super) fn poll(&mut self,policy:&LanPolicy)->io::Result<Option<(bool,Service)>> {
        let mut events=Vec::new();
        for (_,browser) in &self.browsers {
            // Bounded drain prevents DNS-SD input from starving owner checks.
            for _ in 0..32 {match browser.try_recv(){Ok(event)=>events.push(event),Err(mdns_sd::TryRecvError::Empty)=>break,Err(error)=>return Err(denied(error))}}
        }
        for event in events {
            match event {
                ServiceEvent::ServiceResolved(info)=>{
                    if info.get_property("nestlink-proxy").is_some()
                        || !info.get_addresses_v4().contains(&policy.interface_address)
                        || !policy.mdns.iter().any(|rule|rule.allow_export && rule.service_type==info.ty_domain && rule.port==info.port)
                    {continue;}
                    let fingerprint=nestlink_identity::digest(info.fullname.as_bytes());
                    let instance=format!("svc-{}",hex(&fingerprint[..8]));
                    let service=Service {service_type:info.ty_domain.clone(),instance,port:u32::from(info.port),properties:info.get_properties().iter().map(|property|Txt{key:property.key().into(),value:property.val().map(Vec::from)}).collect()};
                    if validate(&service).is_err() || self.local.len()>=MAX_RECORDS && !self.local.contains_key(&info.fullname) {continue;}
                    if self.local.get(&info.fullname)!=Some(&service) {
                        self.queue(false,service.clone());
                        self.local.insert(info.fullname.clone(),service);
                    }
                },
                ServiceEvent::ServiceRemoved(_,fullname)=>{if let Some(service)=self.local.remove(&fullname){self.queue(true,service);}},
                _=>{},
            }
        }
        if self.last_refresh.elapsed()>=Duration::from_secs(3) {
            for service in self.local.values().cloned().collect::<Vec<_>>() {self.queue(false,service);}
            self.last_refresh=Instant::now();
        }
        let expired:Vec<_>=self.remote.iter().filter(|(_,(_,_,seen))|seen.elapsed()>=Duration::from_secs(10)).map(|(key,_)|key.clone()).collect();
        for key in expired {self.remove(&key)?;}
        let mut waiting=Vec::new();
        for receipt in self.pending.drain(..) {
            match receipt.try_recv() {
                Ok(UnregisterStatus::OK)=>{},
                Ok(UnregisterStatus::NotFound)=>return Err(denied("owned DNS-SD record disappeared before unregister acknowledgement")),
                Err(mdns_sd::TryRecvError::Empty)=>waiting.push(receipt),
                Err(error)=>return Err(denied(error)),
            }
        }
        self.pending=waiting;
        Ok(self.output.pop_front())
    }
    fn queue(&mut self,withdraw:bool,service:Service) {
        if self.output.len()<MAX_RECORDS*2 {self.output.push_back((withdraw,service));}
    }
    pub(super) fn receive(&mut self,policy:&LanPolicy,withdraw:bool,service:Service)->io::Result<()> {
        validate(&service)?;
        if !policy.mdns.iter().any(|rule|rule.allow_import && rule.service_type==service.service_type && u32::from(rule.port)==service.port) {
            return Err(denied("DNS-SD service type, port or import direction is not approved"));
        }
        let key=(service.service_type.clone(),service.instance.clone());
        if withdraw {return self.remove(&key);}
        if let Some((_,original,seen))=self.remote.get_mut(&key) {
            if original==&service {*seen=Instant::now();return Ok(());}
        }
        if !self.remote.contains_key(&key) && self.remote.len()>=MAX_RECORDS {return Err(denied("remote DNS-SD catalog is full"));}
        let instance=format!("nl-{}-{}",self.peer_tag,service.instance);
        let host=format!("nl-{}.local.",self.peer_tag);
        let mut properties:Vec<TxtProperty>=service.properties.iter().map(|txt|match &txt.value {
            Some(bytes)=>TxtProperty::from((txt.key.clone(),bytes.as_slice())),None=>TxtProperty::from(txt.key.as_str()),
        }).collect();
        properties.push(TxtProperty::from(("nestlink-proxy","1")));
        let mut record=ServiceInfo::new(&service.service_type,&instance,&host,self.peer_address,service.port as u16,properties).map_err(denied)?;
        record.set_interfaces(vec![IfKind::IndexV4(policy.interface_index)]);
        let fullname=record.get_fullname().to_owned();
        self.daemon.as_ref().ok_or_else(||denied("DNS-SD is disabled"))?.register(record).map_err(denied)?;
        self.remote.insert(key,(fullname,service,Instant::now()));
        Ok(())
    }
    fn remove(&mut self,key:&(String,String))->io::Result<()> {
        if let Some((fullname,_,_))=self.remote.remove(key) {
            let receipt=self.daemon.as_ref().ok_or_else(||denied("DNS-SD stopped"))?.unregister(&fullname).map_err(denied)?;
            self.pending.push(receipt);
        }
        Ok(())
    }
    pub(super) fn shutdown(&mut self,deadline:Instant)->io::Result<()> {
        let keys:Vec<_>=self.remote.keys().cloned().collect();
        let mut failed=None;
        for key in keys {if let Err(error)=self.remove(&key){failed=Some(error);}}
        if let Some(daemon)=self.daemon.take() {
            for (kind,_) in &self.browsers {if let Err(error)=daemon.stop_browse(kind){failed=Some(denied(error));}}
            for receipt in self.pending.drain(..) {
                match receipt.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Ok(UnregisterStatus::OK)=>{},
                    Ok(UnregisterStatus::NotFound)=>failed=Some(denied("owned DNS-SD unregister was not acknowledged")),
                    Err(error)=>failed=Some(denied(error)),
                }
            }
            let receipt=daemon.shutdown().map_err(denied)?;
            if receipt.recv_timeout(deadline.saturating_duration_since(Instant::now())).map_err(denied)?!=DaemonStatus::Shutdown {
                failed=Some(denied("DNS-SD daemon shutdown was not acknowledged"));
            }
        }
        self.local.clear();self.output.clear();self.browsers.clear();
        failed.map_or(Ok(()),Err)
    }
}
impl Drop for Mdns {
    fn drop(&mut self) {if let Some(daemon)=&self.daemon {for (fullname,_,_) in self.remote.values(){let _=daemon.unregister(fullname);}for (kind,_) in &self.browsers{let _=daemon.stop_browse(kind);}let _=daemon.shutdown();}}
}
pub(super) fn validate(service:&Service)->io::Result<()> {
    if !name(&service.instance,32) || service.service_type.len()>64 || service.port==0 || service.port>u16::MAX as u32
        || service.properties.len()>12 || service.properties.iter().map(|p|p.key.len()+p.value.as_ref().map_or(0,Vec::len)).sum::<usize>()>512
        || service.properties.iter().any(|property|property.key.is_empty() || property.key.len()>32 || !property.key.bytes().all(|b|(0x20..=0x7e).contains(&b) && b!=b'=') || property.key.eq_ignore_ascii_case("nestlink-proxy") || property.value.as_ref().is_some_and(|v|v.len()>192))
    {return Err(denied("invalid or oversized explicit DNS-SD description"));}
    let mut keys=std::collections::BTreeSet::new();
    if service.properties.iter().any(|property|!keys.insert(property.key.to_ascii_lowercase())) {return Err(denied("duplicate DNS-SD TXT keys"));}
    Ok(())
}
pub(super) fn hex(bytes:&[u8])->String {bytes.iter().map(|byte|format!("{byte:02x}")).collect()}
