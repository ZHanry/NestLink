//! Review-only HEVC Main8 GPU diagnostic primitives. No wire codec/permission claim.
#![allow(unsafe_code)]
use crate::{VideoConfig, hevc_probe::Validator, windows_mf::Transform};
use std::{
    ffi::c_void,
    io,
    marker::PhantomData,
    ptr::NonNull,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
unsafe extern "C" {
    fn nl_hevc_synthetic_open(width: u32, height: u32, result: *mut *mut c_void) -> i32;
    fn nl_hevc_synthetic_borrow(
        source: *mut c_void,
        device: *mut *mut c_void,
        texture: *mut *mut c_void,
    ) -> i32;
    fn nl_hevc_synthetic_close(source: *mut c_void);
    fn nl_hevc_observation(codec: *mut c_void, luid: *mut u64, flags: *mut u32) -> i32;
}
fn checked(hr: i32) -> io::Result<()> {
    if hr < 0 {
        Err(io::Error::other(format!(
            "HEVC prototype HRESULT {hr:#010x}"
        )))
    } else {
        Ok(())
    }
}
fn authorized(authority: &AtomicBool) -> io::Result<()> {
    if authority.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "HEVC diagnostic owner revoked",
        ))
    }
}
/// Only synthetic NV12 pixels. The source cannot enumerate or capture a desktop.
pub struct HevcSyntheticSource {
    handle: NonNull<c_void>,
    _thread: PhantomData<Rc<()>>,
}
impl HevcSyntheticSource {
    pub fn new(width: u32, height: u32) -> io::Result<Self> {
        let mut handle = std::ptr::null_mut();
        // SAFETY: bounded constructor, initialized output; no borrowed pixels.
        checked(unsafe { nl_hevc_synthetic_open(width, height, &mut handle) })?;
        Ok(Self {
            handle: NonNull::new(handle)
                .ok_or_else(|| io::Error::other("null synthetic source"))?,
            _thread: PhantomData,
        })
    }
    fn borrow(&self) -> io::Result<(*mut c_void, *mut c_void)> {
        let (mut device, mut texture) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: this !Send owner keeps source/device/texture alive on creating thread.
        checked(unsafe {
            nl_hevc_synthetic_borrow(self.handle.as_ptr(), &mut device, &mut texture)
        })?;
        Ok((device, texture))
    }
}
impl Drop for HevcSyntheticSource {
    fn drop(&mut self) {
        // SAFETY: same-thread owned source, after all retained transforms.
        unsafe { nl_hevc_synthetic_close(self.handle.as_ptr()) };
    }
}
#[derive(Debug)]
pub struct HevcBackendObservation {
    pub asynchronous: bool,
    pub d3d_manager: bool,
    pub actual_hardware_output: bool,
    pub gpu_input: bool,
    pub drain_started: bool,
    pub drain_complete: bool,
    pub adapter_luid: Option<u64>,
}
fn observation(transform: &Transform) -> io::Result<HevcBackendObservation> {
    let (mut luid, mut flags) = (0, 0);
    // SAFETY: owned live transform, initialized scalar outputs, owner thread.
    checked(unsafe { nl_hevc_observation(transform.handle.as_ptr(), &mut luid, &mut flags) })?;
    Ok(HevcBackendObservation {
        asynchronous: flags & 1 != 0,
        d3d_manager: flags & 2 != 0,
        actual_hardware_output: flags & 4 != 0,
        gpu_input: flags & 8 != 0,
        drain_started: flags & 16 != 0,
        drain_complete: flags & 32 != 0,
        adapter_luid: (flags & 2 != 0).then_some(luid),
    })
}
pub struct HevcProbePacket {
    pub pts_90khz: u64,
    pub data: Vec<u8>,
}
impl Drop for HevcProbePacket {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.data.zeroize();
    }
}
pub struct HevcProbeEncoder {
    inner: Transform,
    config: VideoConfig,
    validator: Validator,
    scratch: Vec<u8>,
    authority: Arc<AtomicBool>,
}
impl HevcProbeEncoder {
    pub fn new(
        source: &HevcSyntheticSource,
        config: VideoConfig,
        authority: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        authorized(&authority)?;
        let (device, _) = source.borrow()?;
        // SAFETY: same owner/device; native retains its device and four input textures.
        let inner = unsafe { Transform::new_hevc(config, device, true, true) }?;
        Ok(Self {
            inner,
            config,
            validator: Validator::default(),
            scratch: vec![0; 8 * 1024 * 1024],
            authority,
        })
    }
    pub fn submit(
        &mut self,
        source: &HevcSyntheticSource,
        pts: u64,
    ) -> io::Result<(bool, Option<HevcProbePacket>)> {
        authorized(&self.authority)?;
        let (_, texture) = source.borrow()?;
        // SAFETY: synchronous owner-local NV12 pointer, same-device verified natively.
        let (accepted, output) = unsafe {
            self.inner
                .process_gpu(texture, pts, true, &mut self.scratch)
        }?;
        authorized(&self.authority)?;
        let packet = if let Some((length, actual_pts)) = output {
            self.validator.validate(
                &self.scratch[..length],
                self.config.width,
                self.config.height,
            )?;
            Some(HevcProbePacket {
                pts_90khz: actual_pts,
                data: self.scratch[..length].to_vec(),
            })
        } else {
            None
        };
        Ok((accepted, packet))
    }
    pub fn poll(&mut self) -> io::Result<Option<HevcProbePacket>> {
        authorized(&self.authority)?;
        let output = self.inner.receive(&mut self.scratch)?;
        authorized(&self.authority)?;
        if let Some((length, pts)) = output {
            self.validator.validate(
                &self.scratch[..length],
                self.config.width,
                self.config.height,
            )?;
            Ok(Some(HevcProbePacket {
                pts_90khz: pts,
                data: self.scratch[..length].to_vec(),
            }))
        } else {
            Ok(None)
        }
    }
    pub fn begin_drain(&mut self) -> io::Result<()> {
        authorized(&self.authority)?;
        self.inner.begin_hevc_drain()
    }
    pub fn pending_frames(&self) -> usize {
        self.inner.pending_frames()
    }
    pub fn backend(&self) -> io::Result<HevcBackendObservation> {
        observation(&self.inner)
    }
    pub fn profile(&self) -> Option<(u32, u32, u32, u32)> {
        self.validator
            .info()
            .map(|s| (s.profile, s.level, s.width, s.height))
    }
    pub fn close(mut self) -> io::Result<()> {
        self.inner.close()
    }
}
impl Drop for HevcProbeEncoder {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.scratch.zeroize();
    }
}
pub struct HevcProbeDecoder {
    inner: Transform,
    config: VideoConfig,
    validator: Validator,
    scratch: Vec<u8>,
    authority: Arc<AtomicBool>,
}
impl HevcProbeDecoder {
    /// Some(source) requests real same-device DXGI output. None is a separate
    /// synchronous software decoder, never a hardware fallback success claim.
    pub fn new(
        source: Option<&HevcSyntheticSource>,
        config: VideoConfig,
        authority: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        authorized(&authority)?;
        let device = source
            .map(HevcSyntheticSource::borrow)
            .transpose()?
            .map_or(std::ptr::null_mut(), |v| v.0);
        // SAFETY: owner-local device or null software decode; native retains COM references.
        let inner = unsafe { Transform::new_hevc(config, device, false, source.is_some()) }?;
        let size = inner.raw_bytes;
        Ok(Self {
            inner,
            config,
            validator: Validator::default(),
            scratch: vec![0; size],
            authority,
        })
    }
    pub fn submit(
        &mut self,
        packet: &HevcProbePacket,
    ) -> io::Result<(bool, Option<(Vec<u8>, u64)>)> {
        authorized(&self.authority)?;
        let mut next = self.validator.clone();
        next.validate(&packet.data, self.config.width, self.config.height)?;
        let (accepted, output) =
            self.inner
                .process(&packet.data, packet.pts_90khz, false, &mut self.scratch)?;
        authorized(&self.authority)?;
        if accepted {
            self.validator = next;
        }
        Ok((
            accepted,
            output.map(|(size, pts)| (self.scratch[..size].to_vec(), pts)),
        ))
    }
    pub fn poll(&mut self) -> io::Result<Option<(Vec<u8>, u64)>> {
        authorized(&self.authority)?;
        let output = self.inner.receive(&mut self.scratch)?;
        authorized(&self.authority)?;
        Ok(output.map(|(size, pts)| (self.scratch[..size].to_vec(), pts)))
    }
    pub fn begin_drain(&mut self) -> io::Result<()> {
        authorized(&self.authority)?;
        self.inner.begin_hevc_drain()
    }
    pub fn pending_frames(&self) -> usize {
        self.inner.pending_frames()
    }
    pub fn backend(&self) -> io::Result<HevcBackendObservation> {
        observation(&self.inner)
    }
    pub fn close(mut self) -> io::Result<()> {
        self.inner.close()
    }
}
impl Drop for HevcProbeDecoder {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.scratch.zeroize();
    }
}
