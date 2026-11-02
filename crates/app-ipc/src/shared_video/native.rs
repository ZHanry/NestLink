use super::*;
use crate::{NativeVideoBinding,compressed_video::qpc,video::video_binding_is_live,wire::{Command,Reply,Request,Response}};
use nestlink_app_core::{CoreHandle,NativeSessionBinding,SharedVideoConsumer};
use nestlink_local_ipc::{LocalStream,VerifiedLocalPeer};
use std::{path::Path,sync::{Arc,atomic::{AtomicBool,Ordering}},time::Duration};

const AUTHORITY_MS:u64 = 100;
const TRANSFER_BUDGET:Duration = Duration::from_millis(50);

pub(crate) async fn open(connection:&LocalStream,core:&CoreHandle,binding:NativeVideoBinding) -> Result<(SharedVideoContext,SharedVideoConsumer),Error> {
    if !video_binding_is_live(core,&binding) {return Err(Error::Protocol);}
    let peer = connection.verified_peer_process()?;
    if peer.runtime_id() != binding.runtime_id {return Err(Error::Protocol);}
    let consumer = core.open_native_shared_video(&NativeSessionBinding {request_id:binding.request_id.clone(),connection_generation:binding.connection_generation},binding.source,peer.export_target()?).await.map_err(|_| Error::Protocol)?;
    let ring = consumer.ring().map_err(|_| Error::Protocol)?;
    let context = SharedVideoContext {
        media:CompressedContext::from_domain(&binding,consumer.context().clone())?,
        ring_id:ring.ring_id,adapter_luid:ring.adapter_luid,handles:ring.handles,resource_ids:ring.resource_ids,
        width:ring.width,height:ring.height,bytes:ring.bytes,qpc_frequency:qpc()?.1,
    };
    context.validate()?;
    if !video_binding_is_live(core,&binding) {return Err(Error::Protocol);}
    peer.check_current()?;
    Ok((context,consumer))
}
fn authority(consumer:&SharedVideoConsumer,context:&SharedVideoContext) -> Result<u64,Error> {
    let remaining = consumer.authority_remaining().map_err(|_| Error::Protocol)?.min(Duration::from_millis(AUTHORITY_MS));
    let (now,frequency) = qpc()?;
    if frequency != context.qpc_frequency || remaining.is_zero() {return Err(Error::Protocol);}
    let ticks = u64::try_from(remaining.as_nanos()*u128::from(frequency)/1_000_000_000).map_err(|_| Error::Protocol)?;
    now.checked_add(ticks).filter(|deadline| *deadline > now && *deadline <= i64::MAX as u64).ok_or(Error::Protocol)
}
fn check(core:&CoreHandle,consumer:&SharedVideoConsumer,context:&SharedVideoContext,peer:&VerifiedLocalPeer) -> Result<(),Error> {
    peer.check_current()?;
    consumer.check_current().map_err(|_| Error::Protocol)?;
    if !video_binding_is_live(core,&context.binding()) {return Err(Error::Protocol);}
    Ok(())
}
pub(crate) async fn serve(mut connection:LocalStream,core:CoreHandle,context:SharedVideoContext,consumer:SharedVideoConsumer) -> Result<(),Error> {
    let peer = connection.verified_peer_process()?;
    let mut interval = tokio::time::interval(Duration::from_millis(8));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut authority_sequence = 0u64;
    let mut authority_sent = tokio::time::Instant::now() - Duration::from_secs(1);
    let mut native_sequence = 0;
    let mut last_pts = 0;
    loop {
        check(&core,&consumer,&context,&peer)?;
        if authority_sent.elapsed() >= Duration::from_millis(25) {
            authority_sequence = authority_sequence.checked_add(1).filter(|value| *value <= i64::MAX as u64).ok_or(Error::Protocol)?;
            let message = SurfaceMessage::Authority {context:context.clone(),sequence:authority_sequence,not_after_qpc:authority(&consumer,&context)?};
            tokio::time::timeout(TRANSFER_BUDGET,connection.send(&message)).await.map_err(|_| Error::Protocol)??;
            check(&core,&consumer,&context,&peer)?;
            authority_sent = tokio::time::Instant::now();
        }
        if let Some(frame) = consumer.poll().map_err(|_| Error::Protocol)? {
            let surface = frame.shared_surface().map_err(|_| Error::Protocol)?.ok_or(Error::Protocol)?;
            let native = surface.descriptor();
            if frame.sequence <= native_sequence || (native_sequence > 0 && frame.pts_90khz <= last_pts) || native.pts_90khz != frame.pts_90khz {return Err(Error::Protocol);}
            let descriptor = SharedFrameDescriptor {
                context:context.clone(),native_sequence:frame.sequence,token:native.token,pts_90khz:native.pts_90khz,
                slot:native.slot,acquire_key:native.acquire_key,release_key:native.release_key,
                resource_expires_qpc:native.expires_qpc,not_after_qpc:authority(&consumer,&context)?.min(native.expires_qpc),
            };
            descriptor.validate()?;
            check(&core,&consumer,&context,&peer)?;
            surface.begin_transfer().map_err(|_| Error::Protocol)?;
            // Once writing begins, a partial descriptor can never invoke local
            // discard. Only the actual returned GPU mutex key recycles a slot.
            tokio::time::timeout(TRANSFER_BUDGET,connection.send(&SurfaceMessage::Frame {descriptor})).await.map_err(|_| Error::Protocol)??;
            surface.check_current().map_err(|_| Error::Protocol)?;
            check(&core,&consumer,&context,&peer)?;
            native_sequence = frame.sequence; last_pts = frame.pts_90khz;
            // This records successful TLS transfer only. No Presented or
            // decoded-consumption state is inferred from the write result.
        }
        interval.tick().await;
    }
}

pub struct ImportedSharedFrame {
    descriptor:SharedFrameDescriptor,
    peer:VerifiedLocalPeer,
    active:Arc<AtomicBool>,
    ring:nestlink_app_core::TransferredSurfaceRing,
}
impl ImportedSharedFrame {
    pub fn descriptor(&self) -> &SharedFrameDescriptor {&self.descriptor}
    pub fn ring(&self) -> nestlink_app_core::TransferredSurfaceRing {self.ring.clone()}
    /// Retains the authentic transferred resource even after its presentation
    /// deadline. A late/hidden frame may only return the actual native key.
    pub fn check_transfer_owner(&self) -> Result<(),Error> {
        self.peer.check_current()?;
        self.ring.check_current().map_err(|_| Error::Protocol)?;
        self.descriptor.validate()?;
        if !self.active.load(Ordering::Acquire) {return Err(Error::Protocol);}
        Ok(())
    }
    pub fn check_current(&self) -> Result<(),Error> {
        self.check_transfer_owner()?;
        if qpc()?.0 >= self.descriptor.not_after_qpc {return Err(Error::Protocol);}
        Ok(())
    }
}
pub enum SharedVideoMessage {
    Authority {not_after_qpc:u64},
    Frame(ImportedSharedFrame),
}
pub struct SharedVideoClient {
    connection:LocalStream,
    pub context:SharedVideoContext,
    peer:VerifiedLocalPeer,
    active:Arc<AtomicBool>,
    last_sequence:u64,
    last_pts:u64,
    last_token:u64,
    last_keys:[u64;3],
    authority_sequence:u64,
    ring:nestlink_app_core::TransferredSurfaceRing,
}
impl SharedVideoClient {
    pub async fn open(directory:&Path,binding:NativeVideoBinding) -> Result<Self,Error> {
        let mut connection = LocalStream::connect(directory).await?;
        let peer = connection.verified_peer_process()?;
        if peer.runtime_id() != binding.runtime_id || connection.runtime_id() != binding.runtime_id {return Err(Error::Protocol);}
        connection.send(&Request {version:nestlink_local_ipc::VERSION,runtime_id:binding.runtime_id.clone(),sequence:1,expected_generation:binding.ui_generation,
            command:Command::OpenNativeSharedVideo {request_id:binding.request_id.clone(),connection_generation:binding.connection_generation,source:binding.source}}).await?;
        let response:Response = connection.receive().await?;
        if response.version != nestlink_local_ipc::VERSION || response.runtime_id != binding.runtime_id || response.sequence != 1 || response.snapshot.generation != binding.ui_generation
            || response.snapshot.native_session.data.as_ref().is_none_or(|session| session.status != nestlink_app_core::NativeSessionStatus::Connected || session.request_id != binding.request_id || session.connection_generation != binding.connection_generation)
        {return Err(Error::Protocol);}
        let Reply::SharedVideoOpened {context} = response.result else {return Err(Error::Protocol);};
        context.validate()?;
        if context.binding() != binding || context.qpc_frequency != qpc()?.1 {return Err(Error::Protocol);}
        peer.check_current()?;
        let ring = nestlink_app_core::TransferredSurfaceRing::from_authenticated_peer(context.native_ring()?,peer.export_target()?).map_err(|_| Error::Protocol)?;
        Ok(Self {connection,context,peer,active:Arc::new(AtomicBool::new(true)),last_sequence:0,last_pts:0,last_token:0,last_keys:[0;3],authority_sequence:0,ring})
    }
    pub fn ring(&self) -> nestlink_app_core::TransferredSurfaceRing {self.ring.clone()}
    pub async fn receive(&mut self) -> Result<SharedVideoMessage,Error> {
        let result = self.receive_current().await;
        if result.is_err() {self.active.store(false,Ordering::Release);}
        result
    }
    async fn receive_current(&mut self) -> Result<SharedVideoMessage,Error> {
        self.peer.check_current()?;
        if !self.active.load(Ordering::Acquire) {return Err(Error::Protocol);}
        let message:SurfaceMessage = self.connection.receive().await?;
        self.peer.check_current()?;
        let (now,frequency) = qpc()?;
        if frequency != self.context.qpc_frequency {return Err(Error::Protocol);}
        match message {
            SurfaceMessage::Authority {context,sequence,not_after_qpc} => {
                if context != self.context || sequence <= self.authority_sequence || sequence > i64::MAX as u64
                    || not_after_qpc <= now || not_after_qpc.saturating_sub(now) > frequency/10
                {return Err(Error::Protocol);}
                self.authority_sequence = sequence;
                Ok(SharedVideoMessage::Authority {not_after_qpc})
            }
            SurfaceMessage::Frame {descriptor} => {
                descriptor.validate()?;
                if descriptor.context != self.context || descriptor.native_sequence <= self.last_sequence || descriptor.token <= self.last_token
                    || (self.last_sequence > 0 && descriptor.pts_90khz <= self.last_pts)
                    || descriptor.acquire_key <= self.last_keys[descriptor.slot as usize]
                    || descriptor.not_after_qpc <= now || descriptor.not_after_qpc.saturating_sub(now) > frequency/10
                    || descriptor.resource_expires_qpc.saturating_sub(now) > frequency*5
                {return Err(Error::Protocol);}
                self.last_sequence = descriptor.native_sequence; self.last_pts = descriptor.pts_90khz; self.last_token = descriptor.token;
                self.last_keys[descriptor.slot as usize] = descriptor.acquire_key;
                Ok(SharedVideoMessage::Frame(ImportedSharedFrame {descriptor,peer:self.peer.clone(),active:self.active.clone(),ring:self.ring.clone()}))
            }
        }
    }
}
impl Drop for SharedVideoClient {
    fn drop(&mut self) {self.active.store(false,Ordering::Release);}
}
