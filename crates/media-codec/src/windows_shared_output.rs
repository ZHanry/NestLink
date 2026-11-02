//! A finite original-decoder surface export. Public descriptor values are only
//! syntax; the private frame lease, actual process target and native mutex own it.
#![allow(unsafe_code)]
use crate::{VideoConfig, windows_mf::Transform};
use nestlink_platform_security::local_stream::VerifiedProcessExportTarget;
use std::{ffi::c_void, io, os::windows::io::AsRawHandle, sync::{Arc, atomic::{AtomicBool, AtomicU8, Ordering}}};
use sha2::{Digest, Sha256};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SharedRingDescriptor {
    pub ring_id: [u8;16],
    pub adapter_luid: u64,
    pub handles: [u64;3],
    pub resource_ids: [[u8;16];3],
    pub width: u32,
    pub height: u32,
    pub bytes: u64,
}
impl SharedRingDescriptor {
    pub fn validate(&self, config: VideoConfig) -> io::Result<()> {
        if self.ring_id==[0;16] || self.handles.iter().any(|value| *value==0 || usize::try_from(*value).is_err())
            || self.resource_ids.contains(&[0;16]) || self.handles[0]==self.handles[1] || self.handles[0]==self.handles[2] || self.handles[1]==self.handles[2]
            || self.resource_ids[0]==self.resource_ids[1] || self.resource_ids[0]==self.resource_ids[2] || self.resource_ids[1]==self.resource_ids[2]
            || (self.width,self.height)!=(config.width,config.height) || self.width==0 || self.height==0
            || !self.width.is_multiple_of(2) || !self.height.is_multiple_of(2) || self.width>8192 || self.height>8192
            || self.bytes!=u64::from(self.width)*u64::from(self.height)*3/2*3 || self.bytes>128*1024*1024
        {return Err(io::Error::other("original shared ring descriptor invalid"));}
        Ok(())
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SharedFrameDescriptor {
    pub token: u64,
    pub pts_90khz: u64,
    pub acquire_key: u64,
    pub release_key: u64,
    pub expires_qpc: u64,
    pub slot: u32,
    pub reserved: u32,
}
impl SharedFrameDescriptor {
    pub fn validate(&self) -> io::Result<()> {
        if self.token==0 || self.token>i64::MAX as u64 || self.pts_90khz>i64::MAX as u64 || self.slot>=3 || self.reserved!=0
            || self.acquire_key==0 || self.acquire_key>=i64::MAX as u64 || self.acquire_key.is_multiple_of(2)
            || self.release_key!=self.acquire_key+1 || self.expires_qpc==0 || self.expires_qpc>i64::MAX as u64
        {return Err(io::Error::other("original shared frame descriptor invalid"));}
        Ok(())
    }
}
unsafe extern "C" {
    fn nl_mf_enable_shared_output(owner:*mut c_void,process:*mut c_void,ring:*mut SharedRingDescriptor)->i32;
    fn nl_mf_shared_frame(owner:*mut c_void,pts:u64,frame:*mut SharedFrameDescriptor)->i32;
    fn nl_mf_discard_shared_frame(owner:*mut c_void,slot:u32,token:u64)->i32;
    fn nl_mf_shared_frame_status(owner:*mut c_void,slot:u32,token:u64)->i32;
}
fn checked(code:i32)->io::Result<i32> {
    if (0..=1).contains(&code) {Ok(code)} else {Err(io::Error::other(format!("original shared surface failed {code:#010x}")))}
}
struct Pending {frame:SharedFrameDescriptor,status:Arc<AtomicU8>}
pub(crate) struct SharedOutput {
    descriptor:SharedRingDescriptor,
    peer:VerifiedProcessExportTarget,
    authority:Arc<AtomicBool>,
    pending:Vec<Pending>,
}
impl SharedOutput {
    pub(crate) fn enable(owner:&Transform,config:VideoConfig,peer:VerifiedProcessExportTarget,authority:Arc<AtomicBool>)->io::Result<Self> {
        let mut descriptor=SharedRingDescriptor::default();
        peer.with_process_handle(|process| {
            // SAFETY: the capability borrows the exact original OS process;
            // native code retains a duplicate and touches D3D only on this worker.
            checked(unsafe {nl_mf_enable_shared_output(owner.handle.as_ptr(),process.as_raw_handle().cast(),&mut descriptor)}).map(|_| ())
        })?;
        descriptor.validate(config)?;
        Ok(Self {descriptor,peer,authority,pending:Vec::new()})
    }
    pub(crate) fn check(&self)->io::Result<()> {
        if !self.authority.load(Ordering::Acquire) {return Err(io::Error::other("shared decoder authority retired"));}
        self.peer.check_current()
    }
    pub(crate) fn descriptor(&self)->SharedRingDescriptor {self.descriptor}
    pub(crate) fn reap(&mut self,owner:&Transform)->io::Result<()> {
        self.check()?;
        let mut retained=Vec::with_capacity(3);
        for pending in self.pending.drain(..) {
            let code=match pending.status.load(Ordering::Acquire) {
                // This private lease was dropped before descriptor writing.
                2=>{checked(unsafe {nl_mf_discard_shared_frame(owner.handle.as_ptr(),pending.frame.slot,pending.frame.token)})?;1},
                // Even after transfer, only the real native return key frees it.
                1=>checked(unsafe {nl_mf_shared_frame_status(owner.handle.as_ptr(),pending.frame.slot,pending.frame.token)})?,
                0=>0,
                _=>return Err(io::Error::other("invalid original shared lease state")),
            };
            if code==0 {retained.push(pending);}
        }
        self.pending=retained;
        Ok(())
    }
    pub(crate) fn output(&mut self,owner:&Transform,pts:u64)->io::Result<Option<SharedDecodedFrame>> {
        self.reap(owner)?;
        let mut frame=SharedFrameDescriptor::default();
        // SAFETY: original owner-thread transform and fixed initialized ABI.
        let code=checked(unsafe {nl_mf_shared_frame(owner.handle.as_ptr(),pts,&mut frame)})?;
        if code==1 {return Ok(None);}
        frame.validate()?;
        if frame.pts_90khz!=pts || self.pending.len()>=3 {return Err(io::Error::other("shared output ledger differs from native output"));}
        let status=Arc::new(AtomicU8::new(0));
        self.pending.push(Pending {frame,status:status.clone()});
        Ok(Some(SharedDecodedFrame {ring:self.descriptor,frame,status,peer:self.peer.clone(),authority:self.authority.clone()}))
    }
}
/// One actual copied NV12 output. No public constructor, Clone or serde path.
pub struct SharedDecodedFrame {
    ring:SharedRingDescriptor,
    frame:SharedFrameDescriptor,
    status:Arc<AtomicU8>,
    peer:VerifiedProcessExportTarget,
    authority:Arc<AtomicBool>,
}
impl SharedDecodedFrame {
    pub fn ring(&self)->SharedRingDescriptor {self.ring}
    pub fn descriptor(&self)->SharedFrameDescriptor {self.frame}
    pub fn check_current(&self)->io::Result<()> {
        if !self.authority.load(Ordering::Acquire) || self.status.load(Ordering::Acquire)==2 || crate::gpu_qpc()?.0>=self.frame.expires_qpc {
            return Err(io::Error::other("original shared frame retired or expired"));
        }
        self.peer.check_current()
    }
    /// Call before the first asynchronous descriptor write. Any uncertain
    /// transfer thereafter waits for native consumption or retires the ring.
    pub fn begin_transfer(&self)->io::Result<()> {
        self.check_current()?;
        self.status.compare_exchange(0,1,Ordering::AcqRel,Ordering::Acquire)
            .map_err(|_| io::Error::other("original shared frame already transferred or discarded"))?;
        Ok(())
    }
    pub(crate) fn fingerprint(&self)->[u8;32] {
        let mut hash=Sha256::new();hash.update(self.ring.ring_id);hash.update(self.ring.adapter_luid.to_be_bytes());
        hash.update(self.ring.resource_ids[self.frame.slot as usize]);hash.update(self.frame.token.to_be_bytes());
        hash.update(self.frame.pts_90khz.to_be_bytes());hash.update(self.frame.acquire_key.to_be_bytes());
        hash.update(self.frame.release_key.to_be_bytes());hash.update(self.frame.expires_qpc.to_be_bytes());hash.finalize().into()
    }
}
impl Drop for SharedDecodedFrame {
    fn drop(&mut self) {let _=self.status.compare_exchange(0,2,Ordering::AcqRel,Ordering::Acquire);}
}
