//! Same-thread actual NV12 texture encoder, independent of synthetic factories.
//! The caller owns approval, signed format negotiation, epoch and worker join.
//! Exact wire negotiation and local consumer process authority remain separate.
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
pub struct HevcDecodedOutput {
    pub pts_90khz: u64,
    pub bgra: Zeroizing<Vec<u8>>,
    pub owner: OwnerObservation,
    pub local_contract_sha256: [u8; 32],
    pub shared: Option<crate::SharedDecodedFrame>,
}

/// An independent exact hardware decode owner. No software or guessed-device
/// fallback is permitted under a GPU-only exact announcement.
pub struct MfHevcHardwareDecoder {
    inner: Transform,
    target: HevcMain8Contract,
    admission: HevcMain8Admission,
    identity: OwnerObservation,
    authority: Arc<AtomicBool>,
    scratch: Zeroizing<Vec<u8>>,
    failed: bool,
    draining: bool,
    shared: Option<crate::windows_shared_output::SharedOutput>,
}
impl MfHevcHardwareDecoder {
    pub fn owner_observation(&self) -> io::Result<OwnerObservation> {
        self.check()?;
        observation(&self.inner)
    }
    /// # Safety
    /// `device` is a live original ID3D11Device on the current decode worker.
    /// It stays retained until open completes; this owner retains native refs.
    pub unsafe fn with_gpu_device(
        target: HevcMain8Contract,
        device: *mut c_void,
        authority: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        if device.is_null() || !authority.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HEVC decode original device/authority unavailable",
            ));
        }
        // SAFETY: explicit original worker-thread device, hardware-only transform.
        let mut inner = unsafe { Transform::new_hevc_depth(target.config(), device, false, true,target.bit_depth()) }?;
        let identity = match observation(&inner) {
            Ok(identity)
                if identity.adapter_luid.is_some() && identity.driver_version.is_some() =>
            {
                identity
            }
            result => {
                inner.close()?;
                return Err(result.err().unwrap_or_else(|| {
                    io::Error::other("HEVC decode original hardware identity is incomplete")
                }));
            }
        };
        let bytes = inner.raw_bytes;
        let owner = Self {
            inner,
            target,
            admission: HevcMain8Admission::new(target),
            identity,
            authority,
            scratch: Zeroizing::new(vec![0; bytes]),
            failed: false,
            draining: false,
            shared: None,
        };
        owner.check()?;
        Ok(owner)
    }
    fn check(&self) -> io::Result<()> {
        if self.failed || !self.authority.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HEVC original decode owner retired or failed",
            ));
        }
        if !self.identity.same_identity(observation(&self.inner)?) {
            return Err(io::Error::other(
                "HEVC original decode resource/adapter/driver identity changed",
            ));
        }
        if let Some(shared) = &self.shared {
            shared.check()?;
        }
        Ok(())
    }
    pub fn enable_shared_output(
        &mut self,
        peer: nestlink_platform_security::local_stream::VerifiedProcessExportTarget,
    ) -> io::Result<crate::SharedRingDescriptor> {
        self.check()?;
        if self.shared.is_some() {
            return Err(io::Error::other(
                "original shared consumer already configured",
            ));
        }
        let shared = crate::windows_shared_output::SharedOutput::enable(
            &self.inner,
            self.target.config(),
            peer,
            self.authority.clone(),
            self.target.bit_depth(),
        )?;
        let descriptor = shared.descriptor();
        if Some(descriptor.adapter_luid) != self.identity.adapter_luid {
            self.failed = true;
            return Err(io::Error::other(
                "shared ring changed the original decoder adapter",
            ));
        }
        self.shared = Some(shared);
        Ok(descriptor)
    }
    fn reap_shared(&mut self) -> io::Result<()> {
        if let Some(shared) = &mut self.shared {
            shared.reap(&self.inner)?;
        }
        Ok(())
    }
    fn finish(&mut self, output: Option<(usize, u64)>) -> io::Result<Option<HevcDecodedOutput>> {
        self.check()?;
        let Some((size, pts_90khz)) = output else {
            return Ok(None);
        };
        let result = (|| {
            if size != self.inner.raw_bytes {
                return Err(io::Error::other(
                    "HEVC decoded pixels differ from the exact surface budget",
                ));
            }
            let owner = observation(&self.inner)?;
            owner.require_hardware_identity()?;
            self.check()?;
            let shared = self
                .shared
                .as_mut()
                .map(|shared| shared.output(&self.inner, pts_90khz))
                .transpose()?
                .flatten();
            Ok(Some(HevcDecodedOutput {
                pts_90khz,
                bgra: Zeroizing::new(self.scratch[..size].to_vec()),
                owner,
                local_contract_sha256: self.target.digest(),
                shared,
            }))
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn submit(
        &mut self,
        bytes: &[u8],
        pts_90khz: u64,
    ) -> io::Result<(bool, Option<HevcDecodedOutput>)> {
        self.check()?;
        self.reap_shared()?;
        if self.draining {
            return Err(io::Error::other(
                "HEVC drained decoder cannot accept another AU",
            ));
        }
        let mut admission = self.admission.clone();
        admission.validate(bytes)?;
        let (accepted, output) =
            match self
                .inner
                .process(bytes, pts_90khz, false, &mut self.scratch)
            {
                Ok(result) => result,
                Err(error) => {
                    self.failed = true;
                    return Err(error);
                }
            };
        self.check()?;
        if accepted {
            self.admission = admission;
        }
        Ok((accepted, self.finish(output)?))
    }
    pub fn poll(&mut self) -> io::Result<Option<HevcDecodedOutput>> {
        self.check()?;
        self.reap_shared()?;
        let output = match self.inner.receive(&mut self.scratch) {
            Ok(output) => output,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        self.finish(output)
    }
    pub fn begin_drain(&mut self) -> io::Result<()> {
        self.check()?;
        if self.draining {
            return Err(io::Error::other("HEVC decoder already draining"));
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
pub(crate) fn observation(inner: &Transform) -> io::Result<OwnerObservation> {
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
    pub fn owner_observation(&self) -> io::Result<OwnerObservation> {
        self.check()?;
        observation(&self.inner)
    }
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
        let mut inner = unsafe { Transform::new_hevc_depth(target.config(), device, true, true,target.bit_depth()) }?;
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
