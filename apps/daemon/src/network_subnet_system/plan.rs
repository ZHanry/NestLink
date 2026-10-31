use super::*;
use base64::{Engine,engine::general_purpose::URL_SAFE_NO_PAD};
use ipnet::Ipv4Net;
use nestlink_identity::{network::{NetworkVerification,verify_network_grant},subnet::{SubnetGatewayState,verify_subnet_mapping}};
use nestlink_protocol::{network::{GrantClaims,NetworkAccessClaims,IpPrefix,PeerId},network_access::NetworkAccessView,subnet::SubnetMappingClaims};
use std::net::{IpAddr,Ipv4Addr};

pub(super) const MAX_PLAN:u64=65_536;
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub schema_version:u16,
    pub owner_id:String,
    pub process:crate::space_dns_system::ProcessIdentity,
    pub uid:u32,
    pub path:PathBuf,
    pub created_at_ms:u64,
    pub expires_at_ms:u64,
    pub deployment_id:String,
    pub space_id:String,
    pub authority:[u8;32],
    pub local_public:[u8;32],
    pub approved_access:[u8;32],
    pub approved_mapping:[u8;32],
    pub lan_name:String,
    pub lan_index:u32,
    pub lan_gateway:Ipv4Addr,
    pub lan_prefix_len:u8,
    pub physical_endpoints:Vec<IpAddr>,
    pub credentials:NetworkAccessView,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub wireguard:Option<wireguard::Ingress>,
}
pub(super) struct Checked {
    pub mapping:SubnetMappingClaims,
    pub business:NetworkAccessClaims,
    pub local_source:bool,
    pub remote:Vec<IpPrefix>,
}
impl Plan {
    pub fn suffix(&self)->String {self.owner_id.replace('-',"")[..12].into()}
    pub fn namespace(&self)->String {format!("nls{}",self.suffix())}
    pub fn tun(&self)->String {format!("nlt{}",self.suffix())}
    pub fn macvlan(&self)->String {format!("nlm{}",self.suffix())}
    pub fn marker(&self)->String {format!("NestLink:subnet:v1:{}",self.owner_id)}
    pub fn socket(&self)->Result<PathBuf> {
        let path=self.path.with_extension(format!("{}.sock",self.owner_id));
        if path.as_os_str().as_encoded_bytes().len()>100 {return Err(io::Error::other("subnet packet socket path must fit the native Unix bound").into());}
        Ok(path)
    }
    pub fn digest(&self)->Result<[u8;32]> {Ok(nestlink_identity::digest(&serde_json::to_vec(self)?))}
    pub fn checked(&self,fresh:bool)->Result<Checked> {
        self.check(fresh,false)
    }
    /// Initial administrator admission also requires the independently fetched
    /// same-boot lease to be live. Runtime observes newer lease facts through
    /// the original ordinary online owner, never by mutating this fixed plan.
    pub fn initial(&self)->Result<Checked> {self.check(true,true)}
    fn check(&self,fresh:bool,initial_node:bool)->Result<Checked> {
        let wall=system_wall_ms()?;
        if self.schema_version!=1 || !owner_id(&self.owner_id) || !self.process.valid() || self.uid==0 || self.uid>i32::MAX as u32
            || !self.path.is_absolute() || self.created_at_ms==0 || self.created_at_ms>=self.expires_at_ms || self.expires_at_ms-self.created_at_ms>60_000
            || self.authority==[0;32] || self.local_public==[0;32] || self.approved_mapping==[0;32] || self.approved_access==[0;32]
            || self.lan_index==0 || !interface_name(&self.lan_name) || self.lan_prefix_len==0 || self.lan_prefix_len>30
            || (fresh && (self.created_at_ms>wall || wall>=self.expires_at_ms)) {return Err(io::Error::other("invalid or expired exact subnet OS plan").into());}
        self.socket()?;
        let now=if initial_node {wall} else {self.created_at_ms};
        let revoked=std::collections::BTreeSet::new();
        let directory=&self.credentials.address_directory;
        let context=NetworkVerification{authority_key:&self.authority,deployment_id:&self.deployment_id,space_id:&self.space_id,policy_epoch:directory.space.policy_epoch,now_ms:now,revoked_grant_ids:&revoked};
        if directory.space.authority_public_key!=URL_SAFE_NO_PAD.encode(self.authority) || directory.space.deployment_id!=self.deployment_id || directory.space.space_id!=self.space_id {return Err(io::Error::other("subnet plan differs from its independently pinned space").into());}
        let access=verify_network_grant(&nestlink_sdk::network_management::decode_network_grant(&self.credentials.access)?,&context)?;
        let GrantClaims::NetworkAccess(business)=access.claims() else {return Err(io::Error::other("subnet plan requires exact raw-IP business authority").into());};
        if access.digest()!=self.approved_access || self.expires_at_ms>business.scope.expires_at_ms {return Err(io::Error::other("subnet business digest/deadline changed").into());}
        let local=PeerId::from_public_key(&self.local_public);
        let local_source=if business.source==local {true} else if business.destination==local {false} else {return Err(io::Error::other("subnet business does not name this proven local installation").into());};
        let mut selected=self.credentials.subnet_mappings.iter().filter(|view|view.gateway.public_key==self.local_public);
        let mapping=selected.next().ok_or_else(||io::Error::other("local gateway has no explicit mapping/business association"))?;
        if selected.next().is_some() {return Err(io::Error::other("ambiguous local subnet mapping").into());}
        let export=verify_network_grant(&nestlink_sdk::network_management::decode_network_grant(&mapping.route_export)?,&context)?;
        let gateway=SubnetGatewayState{node_id:&mapping.gateway.node_id,public_key:&mapping.gateway.public_key,incarnation:&mapping.gateway.incarnation,mapping_revision:mapping.gateway.mapping_revision,lease_expires_at_ms:mapping.gateway.lease_expires_at_ms};
        let verified=verify_subnet_mapping(&mapping.mapping,&context,export,&gateway)?;
        let claims=verified.claims();
        let (own,remote)=if local_source {(&business.source_prefixes,&business.destination_prefixes)} else {(&business.destination_prefixes,&business.source_prefixes)};
        if verified.digest()!=self.approved_mapping || own.as_slice()!=[claims.alias] || self.expires_at_ms>claims.scope.expires_at_ms
            || !claims.original.network.is_ipv4() || !claims.alias.network.is_ipv4() || remote.is_empty() || remote.len()>2 || remote.iter().any(|prefix|!prefix.network.is_ipv4()) {
            return Err(io::Error::other("this Linux namespace provider requires the exact approved IPv4 mapping and remote prefixes").into());
        }
        let original=net(claims.original)?;let alias=net(claims.alias)?;
        let lan=Ipv4Net::new(self.lan_gateway,self.lan_prefix_len)?;
        if self.lan_gateway==lan.network() || self.lan_gateway==lan.broadcast() || (self.wireguard.is_none()&&(!lan.contains(&original.network()) || !lan.contains(&original.broadcast())))
            || (alias!=original&&alias.contains(&self.lan_gateway)) || self.lan_gateway.is_loopback() || self.lan_gateway.is_link_local() || self.lan_gateway.is_multicast() {
            return Err(io::Error::other("explicit extra gateway address must belong to the selected original LAN").into());
        }
        for prefix in remote {let remote=net(*prefix)?;if overlaps(remote,original)||overlaps(remote,alias)||remote.contains(&self.lan_gateway){return Err(io::Error::other("remote wire route would reflect into this original LAN").into());}}
        if self.physical_endpoints.is_empty() || self.physical_endpoints.len()>8 || self.physical_endpoints.iter().any(|ip|ip.is_unspecified()||ip.is_multicast()||contains_ip(alias,ip)||remote.iter().any(|prefix|net(*prefix).is_ok_and(|network|contains_ip(network,ip)))) {return Err(io::Error::other("subnet plan could capture an original physical carrier endpoint").into());}
        let checked=Checked{mapping:claims.clone(),business:business.clone(),local_source,remote:remote.clone()};
        if let Some(ingress)=&self.wireguard {ingress.check(self,&checked,now)?;}
        Ok(checked)
    }
    pub fn read(path:&Path)->Result<Self> {
        let (bytes,uid)=crate::network_packet_runtime::read_public_plan(path,MAX_PLAN)?;
        let plan:Self=serde_json::from_slice(&bytes)?;
        plan.checked(false)?;
        if plan.uid!=uid || plan.path!=path {return Err(io::Error::other("subnet plan changed its original owner or selected path").into());}
        Ok(plan)
    }
    pub fn save_new(&self)->Result {
        self.initial()?;
        let parent=self.path.parent().ok_or_else(||io::Error::other("subnet plan parent missing"))?;
        nestlink_platform_security::check_private_directory(parent)?;
        nestlink_platform_security::create_private(&self.path,&serde_json::to_vec(self)?)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}
pub(super) fn interface_name(value:&str)->bool {!value.is_empty()&&value.len()<=15&&value!="lo"&&value.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'_'|b'-'|b'.'))}
fn owner_id(value:&str)->bool {value.len()==36&&value.bytes().enumerate().all(|(index,byte)|if matches!(index,8|13|18|23){byte==b'-'}else{byte.is_ascii_digit()||matches!(byte,b'a'..=b'f')})}
pub(super) fn net(prefix:IpPrefix)->Result<Ipv4Net> {prefix.validate()?;let IpAddr::V4(ip)=prefix.network else {return Err(io::Error::other("IPv4 subnet prefix required").into());};Ok(Ipv4Net::new(ip,prefix.prefix_len)?)}
pub(super) fn overlaps(a:Ipv4Net,b:Ipv4Net)->bool {a.contains(&b.network())||b.contains(&a.network())}
fn contains_ip(network:Ipv4Net,ip:&IpAddr)->bool {matches!(ip,IpAddr::V4(ip) if network.contains(ip))}

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub schema_version:u16,
    pub plan_digest:[u8;32],
    pub worker:crate::space_dns_system::ProcessIdentity,
    pub namespace_device:u64,
    pub namespace_inode:u64,
    pub tun_index:u32,
    pub macvlan_index:u32,
    pub socket_device:u64,
    pub socket_inode:u64,
    pub socket_parent_device:u64,
    pub socket_parent_inode:u64,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub wireguard_index:Option<u32>,
}
