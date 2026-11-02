//! Imports original-daemon NV12 resources. It owns no IMFTransform decoder.
use super::{GpuVideoSurface,gpu_qpc};
use crate::{SharedFrameDescriptor,SharedRingDescriptor,TransferredSurfaceRing,VideoConfig};
use std::{ffi::c_void,io,marker::PhantomData,ptr::NonNull,rc::Rc,sync::{Arc,atomic::{AtomicBool,Ordering}}};
unsafe extern "C" {
    fn nl_gpu_shared_open(surface:*mut c_void,ring:*const SharedRingDescriptor,fps:u32,driver:u64,result:*mut *mut c_void)->i32;
    fn nl_gpu_shared_consume(handle:*mut c_void,frame:*const SharedFrameDescriptor,deadline:u64,qpc:*mut u64,consumed:*mut u32,converted:*mut u32,submitted:*mut u32)->i32;
    fn nl_gpu_shared_close(handle:*mut c_void)->i32;
}
fn checked(code:i32)->io::Result<()> {
    if code==0 {Ok(())} else {Err(io::Error::other(format!("original surface import failed {code:#010x}")))}
}
pub struct GpuSharedPresenter {
    handle:Option<NonNull<c_void>>,
    ring:TransferredSurfaceRing,
    authority:Arc<AtomicBool>,
    last_sequence:u64,
    failed:bool,
    _thread:PhantomData<Rc<()>>,
}
/// An actual DXGI submission of an imported original surface, separate from
/// TLS transfer, mutex consumption and the daemon's sealed decode receipt.
pub struct SharedGpuSubmissionReceipt {
    ring:TransferredSurfaceRing,
    authority:Arc<AtomicBool>,
    frame:SharedFrameDescriptor,
    native_sequence:u64,
    submitted_qpc:u64,
    deadline:u64,
}
impl SharedGpuSubmissionReceipt {
    pub fn check_current(&self)->io::Result<()> {
        self.ring.check_current()?;
        if !self.authority.load(Ordering::Acquire) || gpu_qpc()?.0>=self.deadline {return Err(io::Error::other("imported surface submission retired"));}
        Ok(())
    }
    pub fn frame(&self)->SharedFrameDescriptor {self.frame}
    pub fn ring(&self)->SharedRingDescriptor {self.ring.descriptor()}
    pub fn native_sequence(&self)->u64 {self.native_sequence}
    pub fn submitted_qpc(&self)->u64 {self.submitted_qpc}
}
pub struct GpuSharedConsumption {
    pub consumed:bool,
    pub gpu_converted:bool,
    pub submitted:Option<SharedGpuSubmissionReceipt>,
}
impl GpuSharedPresenter {
    pub fn open(surface:&GpuVideoSurface,config:VideoConfig,ring:TransferredSurfaceRing,driver_version:u64,authority:Arc<AtomicBool>)->io::Result<Self> {
        ring.check_current()?;
        ring.descriptor().validate(config)?;
        if !authority.load(Ordering::Acquire) || config.fps==0 || config.fps>120 || driver_version==0 {return Err(io::Error::other("imported surface target retired or invalid"));}
        let mut handle=std::ptr::null_mut();
        // SAFETY: retained UI surface, exact destination-owned handles and a
        // new worker-confined importer. This path opens no decoder transform.
        checked(unsafe {nl_gpu_shared_open(surface.0.0.as_ptr(),&ring.descriptor(),config.fps,driver_version,&mut handle)})?;
        let mut owner=Self {handle:Some(NonNull::new(handle).ok_or_else(|| io::Error::other("null original surface importer"))?),ring,authority,last_sequence:0,failed:false,_thread:PhantomData};
        if let Err(error)=owner.check() {owner.failed=true;return Err(error);}
        Ok(owner)
    }
    fn check(&self)->io::Result<()> {
        self.ring.check_current()?;
        if self.failed || self.handle.is_none() || !self.authority.load(Ordering::Acquire) {return Err(io::Error::other("original surface importer retired"));}
        Ok(())
    }
    pub fn consume(&mut self,frame:SharedFrameDescriptor,native_sequence:u64,deadline:u64)->io::Result<GpuSharedConsumption> {
        let result=(|| {
            self.check()?;frame.validate()?;
            let (now,frequency)=gpu_qpc()?;
            if native_sequence<=self.last_sequence || native_sequence>i64::MAX as u64 || deadline==0 || deadline>frame.expires_qpc
                || frame.expires_qpc.saturating_sub(now)>frequency.saturating_mul(5)
            {return Err(io::Error::other("imported surface frame identity or deadline differs"));}
            let mut qpc=0;let mut consumed=0;let mut converted=0;let mut submitted=0;
            // SAFETY: this worker owns the importer and fixed scalar ABI. Only
            // actual keyed-mutex consumption can return the producer's key.
            checked(unsafe {nl_gpu_shared_consume(self.handle.ok_or_else(|| io::Error::other("importer closed"))?.as_ptr(),&frame,deadline,&mut qpc,&mut consumed,&mut converted,&mut submitted)})?;
            self.check()?;
            if consumed!=1 || converted>1 || submitted>1 || (submitted==1 && (converted!=1 || qpc==0 || qpc>=deadline)) {return Err(io::Error::other("native imported surface result invalid"));}
            self.last_sequence=native_sequence;
            Ok(GpuSharedConsumption {consumed:true,gpu_converted:converted==1,
                submitted:(submitted==1).then(|| SharedGpuSubmissionReceipt {ring:self.ring.clone(),authority:self.authority.clone(),frame,native_sequence,submitted_qpc:qpc,deadline})})
        })();
        if result.is_err() {self.failed=true;}
        result
    }
    pub fn close(mut self)->io::Result<()> {self.close_owner()}
    fn close_owner(&mut self)->io::Result<()> {
        let Some(handle)=self.handle.take() else {return Ok(());};
        // SAFETY: unique native importer destroyed on its original worker.
        checked(unsafe {nl_gpu_shared_close(handle.as_ptr())})
    }
}
impl Drop for GpuSharedPresenter {
    fn drop(&mut self) {
        if let Err(error)=self.close_owner() {eprintln!("original surface importer cleanup failed: {error}");}
    }
}
