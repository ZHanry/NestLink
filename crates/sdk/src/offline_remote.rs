//! Finite independent remote authority on the original proved Session and QUIC
//! business queues. No relay, fake service ACL or renewed online permit exists.
use crate::{DeviceIdentity, Sdk, SdkError, network_management::ConsumedOfflineBundle};
use nestlink_identity::{VerifiedPermit,digest};
use nestlink_protocol::{ALPN,Path,offline::{OfflineBusiness,OfflineDirectTransport,management::OfflineBundleView}};
use nestlink_remote::{ChannelRuntime,RuntimeClock,SessionLifecycle,SessionSetup};
use nestlink_session::{EndpointRole,OfflineRemoteAuthority,OfflineRemoteStatus,Session,SessionBinding,StopReason};
use std::{io,net::SocketAddr,sync::Arc,time::{Duration,SystemTime,UNIX_EPOCH}};
use tokio::task::JoinHandle;

fn wall()->Result<u64,SdkError> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?
        .as_millis().try_into().map_err(|_|SdkError::Invalid)
}
impl crate::offline_channel::Owner for OfflineRemoteAuthority {
    fn claims(&self)->Result<nestlink_protocol::offline::OfflineGrantBundleClaims,SdkError>{Ok(self.claims()?)}
    fn digest(&self)->Result<[u8;32],SdkError>{Ok(self.digest())}
    fn sign(&self,wall:u64,binding:&nestlink_protocol::offline::channel::OfflineChannelBinding)->Result<Vec<u8>,SdkError>{Ok(self.sign_channel_proof(wall,binding)?)}
    fn authenticate(&self,wall:u64,transport:OfflineDirectTransport,peer:&[u8;32])->Result<(),SdkError>{Ok(self.authenticate(wall,transport,peer)?)}
}
struct Inner {
    sdk:Arc<Sdk>,local:Arc<DeviceIdentity>,authority:OfflineRemoteAuthority,
    authority_key:[u8;32],original:VerifiedPermit,binding:SessionBinding,role:EndpointRole,
}
/// Retain this original in-memory owner across stopped carriers. Every attempt
/// and both delivery directions keep its same finite cumulative reservation.
pub struct OfflineRemoteOwner(Arc<Inner>);
pub struct OfflineRemoteListener {owner:Arc<Inner>,socket:SocketOwner}
struct SocketOwner(Option<quinn::Endpoint>);
impl Drop for SocketOwner {
    fn drop(&mut self){if let Some(endpoint)=&self.0 {endpoint.close(1u32.into(),b"offline setup ended");}}
}
impl SocketOwner {
    fn endpoint(&self)->Result<&quinn::Endpoint,SdkError>{self.0.as_ref().ok_or(SdkError::Invalid)}
    fn take(&mut self)->Result<quinn::Endpoint,SdkError>{self.0.take().ok_or(SdkError::Invalid)}
}
pub struct OfflineRemoteRuntime {
    channels:ChannelRuntime,authority:OfflineRemoteAuthority,recovery:Option<JoinHandle<()>>,
}
impl OfflineRemoteRuntime {
    pub fn channels(&mut self)->&mut ChannelRuntime {&mut self.channels}
    pub fn status(&self)->Result<OfflineRemoteStatus,SdkError>{Ok(self.authority.status()?)}
    pub fn stop(&self)->Result<(),SdkError>{self.authority.stop();self.channels.lease_control().stop(StopReason::ExplicitExit)?;Ok(())}
    pub async fn wait_stopped(&mut self)->Result<nestlink_remote::StopReport,SdkError>{
        let result=self.channels.wait_stopped().await;
        if let Some(task)=self.recovery.take(){task.abort();let _=task.await;}
        Ok(result?)
    }
}
impl Drop for OfflineRemoteRuntime {
    fn drop(&mut self){if let Some(task)=self.recovery.take(){task.abort();}}
}
impl Sdk {
    /// Requires the actual online consume receipt for this original process.
    /// A saved bundle, installation key or metadata permit cannot create it.
    pub fn prepare_offline_remote(
        self:&Arc<Self>,local:Arc<DeviceIdentity>,consumed:ConsumedOfflineBundle,
        original:VerifiedPermit,binding:SessionBinding,role:EndpointRole,
    )->Result<OfflineRemoteOwner,SdkError>{
        let (admission,authority_key)=consumed.into_admission();
        let index=match role {EndpointRole::Controller=>0,EndpointRole::Host=>1};
        if admission.local_endpoint()!=index || admission.claims().deployment_id!=self.trust.deployment_id
            || original.issuer()!=self.trust.permit_issuer
            || admission.claims().members[index].installation_id!=local.device_id
            || admission.claims().members[index].public_key!=local.identity.public_key()
            || !matches!(admission.claims().business,OfflineBusiness::RemoteControl{..})
        {return Err(SdkError::Trust);}
        let authority=OfflineRemoteAuthority::new(admission)?;authority.check(wall()?)?;
        Ok(OfflineRemoteOwner(Arc::new(Inner{sdk:self.clone(),local,authority,authority_key,original,binding,role})))
    }
}
impl OfflineRemoteOwner {
    pub fn status(&self)->Result<OfflineRemoteStatus,SdkError>{Ok(self.0.authority.status()?)}
    pub fn stop(&self){self.0.authority.stop();}
    /// Recovery retires offline channels before reading latest management
    /// state. Resuming then requires a fresh current online authorization.
    pub async fn synchronize_online(&self)->Result<OfflineBundleView,SdkError>{
        self.stop();
        let claims=self.0.authority.claims()?;
        let view=self.0.sdk.offline_bundle(&claims.space_id,&claims.bundle_id).await?;
        if view.claims!=claims || view.authority_public_key!=self.0.authority_key{return Err(SdkError::Trust);}
        Ok(view)
    }
    pub fn listen(&self,address:SocketAddr)->Result<OfflineRemoteListener,SdkError>{
        if self.0.role!=EndpointRole::Host || address.ip().is_unspecified() || address.ip().is_multicast(){return Err(SdkError::Invalid);}
        self.0.authority.check(wall()?)?;
        let peer=self.0.authority.claims()?.members[0].public_key;
        let endpoint=nestlink_transport_quic::listener(address,&self.0.local.identity,digest(&peer)).map_err(SdkError::NodeQuic)?;
        Ok(OfflineRemoteListener{owner:self.0.clone(),socket:SocketOwner(Some(endpoint))})
    }
    pub async fn connect(&self,peer:SocketAddr,lifecycle:SessionLifecycle)->Result<OfflineRemoteRuntime,SdkError>{
        if self.0.role!=EndpointRole::Controller || peer.port()==0 || peer.ip().is_unspecified() || peer.ip().is_multicast(){return Err(SdkError::Invalid);}
        self.0.authority.reserve_attempt(wall()?,OfflineDirectTransport::Quic)?;
        let key=self.0.authority.claims()?.members[1].public_key;
        let bind=if peer.is_ipv4(){"0.0.0.0:0"}else{"[::]:0"}.parse().map_err(|_|SdkError::Invalid)?;
        let endpoint=nestlink_transport_quic::connector(bind,&self.0.local.identity,digest(&key)).map_err(SdkError::NodeQuic)?;
        let mut socket=SocketOwner(Some(endpoint));
        let connection=nestlink_transport_quic::connect(socket.endpoint()?,peer,self.0.budget()?).await.map_err(SdkError::NodeQuic)?;
        self.0.finish(connection,socket.take()?,lifecycle).await
    }
}
impl OfflineRemoteListener {
    pub fn address(&self)->Result<SocketAddr,SdkError>{Ok(self.socket.endpoint()?.local_addr()?)}
    pub async fn accept(mut self,lifecycle:SessionLifecycle)->Result<OfflineRemoteRuntime,SdkError>{
        let incoming=tokio::time::timeout(self.owner.budget()?,self.socket.endpoint()?.accept()).await.map_err(|_|SdkError::Timeout)?.ok_or(SdkError::Invalid)?;
        self.owner.authority.reserve_attempt(wall()?,OfflineDirectTransport::Quic)?;
        let connection=tokio::time::timeout(self.owner.budget()?,incoming).await.map_err(|_|SdkError::Timeout)?.map_err(io::Error::other)?;
        let endpoint=self.socket.take()?;
        self.owner.finish(connection,endpoint,lifecycle).await
    }
}
impl Inner {
    fn budget(&self)->Result<Duration,SdkError>{self.authority.check(wall()?)?;Ok(self.authority.status()?.remaining_lifetime.min(Duration::from_secs(3)))}
    async fn finish(self:&Arc<Self>,connection:quinn::Connection,endpoint:quinn::Endpoint,lifecycle:SessionLifecycle)->Result<OfflineRemoteRuntime,SdkError>{
        let mut socket=SocketOwner(Some(endpoint));
        let index=match self.role {EndpointRole::Controller=>0,EndpointRole::Host=>1};
        let peer=self.authority.claims()?.members[1-index].public_key;
        let actual=connection.peer_identity().ok_or(SdkError::Trust)?;
        let protocol=connection.handshake_data().and_then(|data|data.downcast::<quinn::crypto::rustls::HandshakeData>().ok()).and_then(|data|data.protocol);
        if protocol.as_deref()!=Some(ALPN.as_bytes()) || nestlink_transport_stream::tls::peer_identity_fingerprint(actual.as_ref()).map_err(|_|SdkError::Trust)?!=digest(&peer){return Err(SdkError::Trust);}
        tokio::time::timeout(self.budget()?,async {
            let (mut send,mut recv)=match self.role {EndpointRole::Controller=>connection.open_bi().await,EndpointRole::Host=>connection.accept_bi().await}.map_err(io::Error::other)?;
            crate::offline_channel::prove(&self.authority,&self.local,&mut recv,&mut send,index as u8,OfflineDirectTransport::Quic,&peer).await?;
            send.finish().map_err(io::Error::other)?;
            if !recv.read_to_end(0).await.map_err(io::Error::other)?.is_empty(){return Err(SdkError::Invalid);}
            Ok::<_,SdkError>(())
        }).await.map_err(|_|SdkError::Timeout)??;
        let clock=RuntimeClock::default();
        let session=Session::activate_offline(self.original.clone(),self.binding.clone(),self.authority.clone(),clock.sample()?)?;
        let channels=nestlink_remote::quic::authorize(connection,Some(socket.take()?),SessionSetup{session,path:Path::Direct,role:self.role,clock,lifecycle},&self.local.identity,&peer).await?;
        let owner=self.clone();let lease=channels.lease_control();
        let recovery=tokio::spawn(async move{
            loop {
                let Ok(remaining)=lease.remaining() else{break;};
                tokio::time::sleep(remaining.min(Duration::from_secs(2))).await;
                if lease.remaining().is_err(){break;}
                let space=match owner.authority.claims(){Ok(c)=>c.space_id,Err(_)=>break};
                if owner.sdk.offline_policy(&space).await.is_ok(){
                    owner.authority.stop();let _=lease.stop(StopReason::Revoked);break;
                }
            }
        });
        Ok(OfflineRemoteRuntime{channels,authority:self.authority.clone(),recovery:Some(recovery)})
    }
}
