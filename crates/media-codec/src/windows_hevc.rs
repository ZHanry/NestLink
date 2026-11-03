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
    fn nl_hevc_hdr10_synthetic_open(width: u32, height: u32, result: *mut *mut c_void) -> i32;
    fn nl_hevc_synthetic_open(
        width: u32,
        height: u32,
        bit_depth: u32,
        result: *mut *mut c_void,
    ) -> i32;
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
    bit_depth: u8,
    hdr10: bool,
    _thread: PhantomData<Rc<()>>,
}
impl HevcSyntheticSource {
    pub fn new(width: u32, height: u32) -> io::Result<Self> {
        Self::with_depth(width, height, 8)
    }
    pub fn with_depth(width: u32, height: u32, bit_depth: u8) -> io::Result<Self> {
        Self::with_color(width, height, bit_depth, false)
    }
    pub fn hdr10(width: u32, height: u32) -> io::Result<Self> {
        Self::with_color(width, height, 10, true)
    }
    fn with_color(width: u32, height: u32, bit_depth: u8, hdr10: bool) -> io::Result<Self> {
        let mut handle = std::ptr::null_mut();
        // SAFETY: bounded constructor, initialized output; no borrowed pixels.
        checked(unsafe {
            if hdr10 {
                nl_hevc_hdr10_synthetic_open(width, height, &mut handle)
            } else {
                nl_hevc_synthetic_open(width, height, u32::from(bit_depth), &mut handle)
            }
        })?;
        Ok(Self {
            handle: NonNull::new(handle)
                .ok_or_else(|| io::Error::other("null synthetic source"))?,
            bit_depth,
            hdr10,
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
pub(crate) fn observation(transform: &Transform) -> io::Result<HevcBackendObservation> {
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
    inner: crate::hevc_encoder::Encoder,
    config: VideoConfig,
    validator: Validator,
    scratch: Vec<u8>,
    rejection_logged: bool,
    authority: Arc<AtomicBool>,
}
impl HevcProbeEncoder {
    pub fn owner_observation(&self) -> io::Result<crate::OwnerObservation> {
        authorized(&self.authority)?;
        self.inner.owner_observation()
    }
    pub fn new(
        source: &HevcSyntheticSource,
        config: VideoConfig,
        authority: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        Self::new_with_backend(
            source,
            config,
            authority,
            crate::HevcEncoderBackend::SystemMf,
        )
    }
    pub fn new_with_backend(
        source: &HevcSyntheticSource,
        config: VideoConfig,
        authority: Arc<AtomicBool>,
        backend: crate::HevcEncoderBackend,
    ) -> io::Result<Self> {
        authorized(&authority)?;
        let (device, _) = source.borrow()?;
        // SAFETY: same owner/device; native retains its device and four input textures.
        let inner = unsafe {
            if source.hdr10 {
                crate::hevc_encoder::Encoder::open_color(config, device, 10, backend, true)
            } else {
                crate::hevc_encoder::Encoder::open(config, device, source.bit_depth, backend)
            }
        }?;
        Ok(Self {
            inner,
            config,
            validator: if source.hdr10 {
                Validator::exact_hdr10()
            } else if source.bit_depth == 10 {
                Validator::exact_main10()
            } else {
                // Apply the same exact contract used by the direction workload
                // before returning a packet. This also retains the bounded
                // original parameter NALs when native timing syntax is rejected.
                Validator::exact_main8()
            },
            scratch: vec![0; 8 * 1024 * 1024],
            rejection_logged: false,
            authority,
        })
    }
    fn validate_output(&mut self, length: usize) -> io::Result<()> {
        let data = &self.scratch[..length];
        let result = self
            .validator
            .validate(data, self.config.width, self.config.height);
        if result.is_err() && !self.rejection_logged {
            self.rejection_logged = true;
            // A bounded original parameter-set record helps distinguish native
            // encoder signalling from parser errors. No VCL/pixel bytes are logged,
            // and the exact original validator result still controls acceptance.
            if let Ok(nals) = crate::h264::nals(data) {
                for nal in nals
                    .into_iter()
                    .filter(|nal| {
                        nal.first()
                            .is_some_and(|byte| (32..=34).contains(&((byte >> 1) & 63)))
                    })
                    .take(3)
                {
                    let recorded = &nal[..nal.len().min(256)];
                    let backend = match self.inner.backend() {
                        crate::HevcEncoderBackend::SystemMf => "mf",
                        crate::HevcEncoderBackend::AmdAmf => "amf",
                    };
                    eprintln!(
                        "hevc_{backend}_rejected_parameter_set kind={} bytes={} recorded={} hex={recorded:02x?}",
                        (nal[0] >> 1) & 63,
                        nal.len(),
                        recorded.len(),
                    );
                }
            }
        }
        result
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
            self.validate_output(length)?;
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
            self.validate_output(length)?;
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
        self.inner.backend_observation()
    }
    pub fn runtime_version(&self) -> io::Result<Option<u64>> {
        self.inner.runtime_version()
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
/// A diagnostic BGRA picture paired with the actual MF output PTS.
pub type HevcProbePicture = (Vec<u8>, u64);
/// Input acceptance and an optional independently timestamped decoded picture.
pub type HevcProbeDecodeStep = (bool, Option<HevcProbePicture>);
pub struct HevcProbeDecoder {
    inner: Transform,
    config: VideoConfig,
    validator: Validator,
    scratch: Vec<u8>,
    authority: Arc<AtomicBool>,
}
impl HevcProbeDecoder {
    pub fn owner_observation(&self) -> io::Result<crate::OwnerObservation> {
        authorized(&self.authority)?;
        crate::windows_hevc_owner::observation(&self.inner)
    }
    /// Some(source) requests real same-device DXGI output. None is a separate
    /// synchronous software decoder, never a hardware fallback success claim.
    pub fn new(
        source: Option<&HevcSyntheticSource>,
        config: VideoConfig,
        authority: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        Self::with_depth(source, config, authority, 8)
    }
    pub fn with_depth(
        source: Option<&HevcSyntheticSource>,
        config: VideoConfig,
        authority: Arc<AtomicBool>,
        bit_depth: u8,
    ) -> io::Result<Self> {
        Self::with_color(source, config, authority, bit_depth, false)
    }
    pub fn with_color(
        source: Option<&HevcSyntheticSource>,
        config: VideoConfig,
        authority: Arc<AtomicBool>,
        bit_depth: u8,
        hdr10: bool,
    ) -> io::Result<Self> {
        authorized(&authority)?;
        if source.is_some_and(|source| source.bit_depth != bit_depth || source.hdr10 != hdr10) {
            return Err(io::Error::other("HEVC synthetic source depth differs"));
        }
        let device = source
            .map(HevcSyntheticSource::borrow)
            .transpose()?
            .map_or(std::ptr::null_mut(), |v| v.0);
        // SAFETY: owner-local device or null software decode; native retains COM references.
        let inner = unsafe {
            Transform::new_hevc_color(config, device, false, source.is_some(), bit_depth, hdr10)
        }?;
        let size = inner.raw_bytes;
        Ok(Self {
            inner,
            config,
            validator: if hdr10 {
                Validator::exact_hdr10()
            } else if bit_depth == 10 {
                Validator::exact_main10()
            } else {
                Validator::default()
            },
            scratch: vec![0; size],
            authority,
        })
    }
    pub fn submit(&mut self, packet: &HevcProbePacket) -> io::Result<HevcProbeDecodeStep> {
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
    pub fn poll(&mut self) -> io::Result<Option<HevcProbePicture>> {
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
