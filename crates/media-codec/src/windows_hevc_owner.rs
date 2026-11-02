//! Same-thread actual NV12 texture encoder, independent of synthetic factories.
//! The caller owns approval, signed format negotiation, epoch and worker join.
//! This primitive does not enable HEVC on the current H264-only product wire.
#![allow(unsafe_code)]
use crate::{HevcMain8Admission, HevcMain8Contract, OwnerObservation, windows_mf::Transform};
use std::{
    ffi::c_void,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;

pub struct HevcOwnerOutput {
    pub pts_90khz: u64,
    pub data: Zeroizing<Vec<u8>>,
    pub owner: OwnerObservation,
    pub local_contract_sha256: [u8; 32],
}

/// COM/D3D objects remain !Send on the original capture/encoding worker.
/// Input acceptance and an actual output are separate facts.
pub struct MfHevcTextureEncoder {
    inner: Transform,
    target: HevcMain8Contract,
    admission: HevcMain8Admission,
    identity: OwnerObservation,
    authority: Arc<AtomicBool>,
    scratch: Zeroizing<Vec<u8>>,
    failed: bool,
    draining: bool,
}
fn observation(inner: &Transform) -> io::Result<OwnerObservation> {
    unsafe extern "C" {
        fn nl_mf_owner_observation(
            handle: *mut c_void,
            out: *mut crate::owner_observation::RawOwnerObservation,
        ) -> i32;
    }
    let mut raw = crate::owner_observation::RawOwnerObservation::default();
    // SAFETY: exact same-thread live MF transform, initialized scalar output.
    let code = unsafe { nl_mf_owner_observation(inner.handle.as_ptr(), &mut raw) };
    if code < 0 {
        return Err(io::Error::other(format!(
            "HEVC owner observation failed {code:#010x}"
        )));
    }
    raw.try_into()
}
impl MfHevcTextureEncoder {
    /// # Safety
    /// `device` is a live ID3D11Device on this thread, retained throughout open.
    /// Every input texture must belong to that original device and worker.
    pub unsafe fn with_gpu_device(
        target: HevcMain8Contract,
        device: *mut c_void,
        authority: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        if device.is_null() || !authority.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HEVC original device/authority unavailable",
            ));
        }
        // SAFETY: caller supplies the original owner-thread device; MF retains COM refs.
        let mut inner = unsafe { Transform::new_hevc(target.config(), device, true, true) }?;
        let identity = match observation(&inner) {
            Ok(identity)
                if identity.adapter_luid.is_some() && identity.driver_version.is_some() =>
            {
                identity
            }
            result => {
                inner.close()?;
                return Err(result.err().unwrap_or_else(|| {
                    io::Error::other("HEVC original hardware identity is incomplete")
                }));
            }
        };
        let owner = Self {
            inner,
            target,
            admission: HevcMain8Admission::new(target),
            identity,
            authority,
            scratch: Zeroizing::new(vec![0; 8 * 1024 * 1024]),
            failed: false,
            draining: false,
        };
        owner.check()?;
        Ok(owner)
    }
    fn check(&self) -> io::Result<()> {
        if self.failed || !self.authority.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HEVC original owner retired or failed",
            ));
        }
        if !self.identity.same_identity(observation(&self.inner)?) {
            return Err(io::Error::other(
                "HEVC original resource/adapter/driver identity changed",
            ));
        }
        Ok(())
    }
    fn finish(&mut self, output: Option<(usize, u64)>) -> io::Result<Option<HevcOwnerOutput>> {
        self.check()?;
        let Some((size, pts_90khz)) = output else {
            return Ok(None);
        };
        let result = (|| {
            self.admission.validate(&self.scratch[..size])?;
            let owner = observation(&self.inner)?;
            owner.require_hardware_identity()?;
            self.check()?;
            Ok(Some(HevcOwnerOutput {
                pts_90khz,
                data: Zeroizing::new(self.scratch[..size].to_vec()),
                owner,
                local_contract_sha256: self.target.digest(),
            }))
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// # Safety
    /// `texture` is live NV12 at the exact target on the constructor's original
    /// device/thread. The native bridge rechecks device identity and geometry.
    pub unsafe fn submit_texture(
        &mut self,
        texture: *mut c_void,
        pts_90khz: u64,
    ) -> io::Result<(bool, Option<HevcOwnerOutput>)> {
        self.check()?;
        if self.draining {
            return Err(io::Error::other(
                "HEVC drained owner cannot accept another texture",
            ));
        }
        // SAFETY: caller-owned same-device NV12 texture; native copies into bounded tracked slots.
        let result = unsafe {
            self.inner
                .process_gpu(texture, pts_90khz, true, &mut self.scratch)
        };
        let (accepted, output) = match result {
            Ok(result) => result,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        Ok((accepted, self.finish(output)?))
    }
    pub fn poll(&mut self) -> io::Result<Option<HevcOwnerOutput>> {
        self.check()?;
        let output = match self.inner.receive(&mut self.scratch) {
            Ok(output) => output,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        self.finish(output)
    }
    /// Ends this original stream once; polling never resubmits accepted input.
    pub fn begin_drain(&mut self) -> io::Result<()> {
        self.check()?;
        if self.draining {
            return Err(io::Error::other("HEVC stream already draining"));
        }
        self.inner.begin_hevc_drain()?;
        self.draining = true;
        Ok(())
    }
    pub fn pending_frames(&self) -> usize {
        self.inner.pending_frames()
    }
    pub fn close(mut self) -> io::Result<()> {
        self.failed = true;
        self.inner.close()
    }
}
