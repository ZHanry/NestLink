//! Live Media Foundation H.264 resources, confined to their creating worker.
//! The initial bridge uses CPU BGRA/NV12 conversion and readback. Its hardware
//! transform flag does not imply a zero-copy capture-to-presentation pipeline.
#![allow(unsafe_code)]
use crate::{
    EncodedVideo, H264EncodingLimits, H264SpsInfo, H264Validator, VideoConfig, VideoEncodeStep,
};
use std::{collections::VecDeque, ffi::c_void, io, marker::PhantomData, ptr::NonNull, rc::Rc};

const PACKET_BYTES: usize = 8 * 1024 * 1024;
unsafe extern "C" {
    fn nl_mf_open(
        encoder: u32,
        hardware: u32,
        width: u32,
        height: u32,
        fps: u32,
        kbps: u32,
        level: u32,
        result: *mut *mut c_void,
    ) -> i32;
    fn nl_mf_process(
        handle: *mut c_void,
        input: *const u8,
        length: usize,
        pts: u64,
        keyframe: u32,
        submit: u32,
        output: *mut u8,
        capacity: usize,
        written: *mut usize,
        output_pts: *mut u64,
    ) -> i32;
    fn nl_mf_open_gpu(
        device: *mut c_void,
        width: u32,
        height: u32,
        fps: u32,
        kbps: u32,
        level: u32,
        result: *mut *mut c_void,
    ) -> i32;
    fn nl_mf_process_gpu(
        handle: *mut c_void,
        texture: *mut c_void,
        pts: u64,
        keyframe: u32,
        submit: u32,
        output: *mut u8,
        capacity: usize,
        written: *mut usize,
        output_pts: *mut u64,
    ) -> i32;
    fn nl_mf_bitrate(handle: *mut c_void, kbps: u32) -> i32;
    fn nl_mf_flush_decoder(handle: *mut c_void) -> i32;
    fn nl_mf_close_checked(handle: *mut c_void) -> i32;
    fn nl_mf_hardware_used(handle: *mut c_void) -> u32;
}

fn geometry(config: VideoConfig) -> io::Result<usize> {
    let bytes = u64::from(config.width) * u64::from(config.height) * 4;
    if config.width == 0
        || config.height == 0
        || !config.width.is_multiple_of(2)
        || !config.height.is_multiple_of(2)
        || config.width > 8192
        || config.height > 8192
        || bytes > 64 * 1024 * 1024
        || !(1..=120).contains(&config.fps)
        || !(64..=100_000).contains(&config.bitrate_kbps)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported H.264 configuration",
        ));
    }
    Ok(bytes as usize)
}
fn failed(stage: &'static str, code: i32) -> io::Error {
    io::Error::other(format!(
        "Media Foundation H.264 {stage} failed ({code:#010x})"
    ))
}
#[derive(Default)]
struct TimestampLedger {
    last_input: Option<u64>,
    last_output: Option<u64>,
    pending: VecDeque<u64>,
}
impl TimestampLedger {
    fn record(
        &mut self,
        code: i32,
        pts: u64,
        written: usize,
        capacity: usize,
        output_pts: u64,
    ) -> io::Result<(bool, Option<(usize, u64)>)> {
        if !(0..=3).contains(&code) {
            return Err(io::Error::other("invalid Media Foundation progress status"));
        }
        let accepted = code <= 1;
        if accepted {
            self.last_input = Some(pts);
            self.pending.push_back(pts);
        }
        if code == 1 || code == 3 {
            if written != 0 {
                return Err(io::Error::other("unexpected H.264 output metadata"));
            }
            return Ok((accepted, None));
        }
        if written == 0
            || written > capacity
            || self.pending.front() != Some(&output_pts)
            || self
                .last_output
                .is_some_and(|previous| output_pts <= previous)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid H.264 output size or timestamp",
            ));
        }
        self.pending.pop_front();
        self.last_output = Some(output_pts);
        Ok((accepted, Some((written, output_pts))))
    }
}
pub(super) struct Transform {
    pub(super) handle: NonNull<c_void>,
    pub(super) raw_bytes: usize,
    timestamps: TimestampLedger,
    failed: bool,
    closed: bool,
    // COM initialization/shutdown and transform calls stay on one worker.
    _thread: PhantomData<Rc<()>>,
}
impl Transform {
    pub(super) fn begin_hevc_drain(&mut self) -> io::Result<()> {
        unsafe extern "C" {
            fn nl_hevc_begin_drain(handle: *mut c_void) -> i32;
        }
        if self.failed || self.closed {
            return Err(io::Error::other("failed HEVC owner cannot drain"));
        }
        // SAFETY: owned live owner-thread transform; native rejects repeats/non-HEVC.
        let hr = unsafe { nl_hevc_begin_drain(self.handle.as_ptr()) };
        if hr < 0 {
            self.failed = true;
            return Err(io::Error::other(format!(
                "HEVC begin drain failed {hr:#010x}"
            )));
        }
        Ok(())
    }
    pub(super) fn pending_frames(&self) -> usize {
        self.timestamps.pending.len()
    }
    /// Prototype-only explicit HEVC open; pump/PTS/teardown are shared with H.264.
    pub(super) unsafe fn new_hevc(
        config: VideoConfig,
        device: *mut c_void,
        encoder: bool,
        hardware: bool,
    ) -> io::Result<Self> {
        unsafe extern "C" {
            fn nl_hevc_open(
                device: *mut c_void,
                encoder: u32,
                hardware: u32,
                width: u32,
                height: u32,
                fps: u32,
                kbps: u32,
                result: *mut *mut c_void,
            ) -> i32;
        }
        let raw_bytes = geometry(config)?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: caller retains an owner-thread D3D device, or null for software decode.
        let hr = unsafe {
            nl_hevc_open(
                device,
                encoder.into(),
                hardware.into(),
                config.width,
                config.height,
                config.fps,
                config.bitrate_kbps,
                &mut handle,
            )
        };
        if hr < 0 {
            return Err(failed("HEVC creation", hr));
        }
        Ok(Self {
            handle: NonNull::new(handle).ok_or_else(|| failed("HEVC null transform", hr))?,
            raw_bytes,
            timestamps: TimestampLedger::default(),
            failed: false,
            closed: false,
            _thread: PhantomData,
        })
    }
    fn new(config: VideoConfig, encoder: bool, hardware: bool, level: u8) -> io::Result<Self> {
        let raw_bytes = geometry(config)?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: bounded scalar configuration and initialized output. The
        // bridge returns one owned transform, or null on every failure path.
        let code = unsafe {
            nl_mf_open(
                encoder.into(),
                hardware.into(),
                config.width,
                config.height,
                config.fps,
                config.bitrate_kbps,
                level.into(),
                &mut handle,
            )
        };
        if code < 0 {
            return Err(failed("creation", code));
        }
        Ok(Self {
            handle: NonNull::new(handle).ok_or_else(|| failed("creation", code))?,
            raw_bytes,
            timestamps: TimestampLedger::default(),
            failed: false,
            closed: false,
            _thread: PhantomData,
        })
    }
    unsafe fn new_gpu(config: VideoConfig, device: *mut c_void, level: u8) -> io::Result<Self> {
        let raw_bytes = geometry(config)?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: caller supplies a live owner-thread D3D11 device; bridge retains it.
        let code = unsafe {
            nl_mf_open_gpu(
                device,
                config.width,
                config.height,
                config.fps,
                config.bitrate_kbps,
                u32::from(level),
                &mut handle,
            )
        };
        if code < 0 {
            return Err(failed("GPU creation", code));
        }
        Ok(Self {
            handle: NonNull::new(handle).ok_or_else(|| failed("GPU creation", code))?,
            raw_bytes,
            timestamps: TimestampLedger::default(),
            failed: false,
            closed: false,
            _thread: PhantomData,
        })
    }
    pub(super) unsafe fn process_gpu(
        &mut self,
        texture: *mut c_void,
        pts: u64,
        keyframe: bool,
        output: &mut [u8],
    ) -> io::Result<(bool, Option<(usize, u64)>)> {
        if self.failed
            || texture.is_null()
            || self.timestamps.last_input.is_some_and(|last| pts <= last)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stale GPU input",
            ));
        }
        let mut written = 0;
        let mut output_pts = 0;
        // SAFETY: caller's NV12 texture is live on this device and owner thread.
        let code = unsafe {
            nl_mf_process_gpu(
                self.handle.as_ptr(),
                texture,
                pts,
                keyframe.into(),
                (self.timestamps.pending.len() < 16).into(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
                &mut output_pts,
            )
        };
        if code < 0 {
            self.failed = true;
            return Err(failed("GPU processing", code));
        }
        let result = self
            .timestamps
            .record(code, pts, written, output.len(), output_pts);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub(super) fn process(
        &mut self,
        input: &[u8],
        pts: u64,
        keyframe: bool,
        output: &mut [u8],
    ) -> io::Result<(bool, Option<(usize, u64)>)> {
        self.exchange(input, pts, keyframe, output, true)
    }
    pub(super) fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<(usize, u64)>> {
        // No-submit receive: decoder poll or explicit HEVC finite-stream EOS drain.
        // The placeholder is never submitted to the MFT.
        let pts = self.timestamps.last_input.map_or(0, |pts| pts + 1);
        Ok(self.exchange(&[0], pts, false, output, false)?.1)
    }
    fn exchange(
        &mut self,
        input: &[u8],
        pts: u64,
        keyframe: bool,
        output: &mut [u8],
        submit: bool,
    ) -> io::Result<(bool, Option<(usize, u64)>)> {
        if self.failed
            || self
                .timestamps
                .last_input
                .is_some_and(|previous| pts <= previous)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "failed H.264 context or stale input timestamp",
            ));
        }
        let mut written = 0;
        let mut output_pts = 0;
        // SAFETY: exclusively borrowed owned transform, bounded input/output
        // slices, synchronous call and valid initialized metadata out pointers.
        let code = unsafe {
            nl_mf_process(
                self.handle.as_ptr(),
                input.as_ptr(),
                input.len(),
                pts,
                keyframe.into(),
                (submit && self.timestamps.pending.len() < 16).into(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
                &mut output_pts,
            )
        };
        if code < 0 {
            self.failed = true;
            return Err(failed("processing", code));
        }
        let progress = self
            .timestamps
            .record(code, pts, written, output.len(), output_pts);
        if progress.is_err() {
            self.failed = true;
        }
        progress
    }
}
impl Transform {
    pub(super) fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // SAFETY: single owner on its creating thread. Timeout quarantines native
        // state; its input textures must not be reused or released elsewhere.
        let code = unsafe { nl_mf_close_checked(self.handle.as_ptr()) };
        if code < 0 {
            return Err(failed("cleanup (native state quarantined)", code));
        }
        Ok(())
    }
}
impl Drop for Transform {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("{error}");
        }
    }
}

pub struct MfH264Encoder {
    inner: Transform,
    scratch: Vec<u8>,
    validator: H264Validator,
    parameters: Vec<u8>,
    recovery_requested: Option<u64>,
    limits: Option<H264EncodingLimits>,
    config: VideoConfig,
}
impl MfH264Encoder {
    pub fn new(config: VideoConfig, hardware_only: bool) -> io::Result<Self> {
        Self::with_limits(config, hardware_only, None)
    }
    pub fn with_limits(
        config: VideoConfig,
        hardware_only: bool,
        limits: Option<H264EncodingLimits>,
    ) -> io::Result<Self> {
        if let Some(limits) = limits {
            limits.validate_config(config)?;
        }
        Ok(Self {
            inner: Transform::new(
                config,
                true,
                hardware_only,
                limits.map_or(0, |limits| limits.max_level_idc),
            )?,
            scratch: vec![0; PACKET_BYTES],
            validator: if let Some(limits) = limits {
                H264Validator::with_limits(config.width, config.height, limits)?
            } else {
                H264Validator::new(config.width, config.height)?
            },
            parameters: Vec::new(),
            recovery_requested: Some(0),
            limits,
            config,
        })
    }
    /// Creates a hardware surface encoder on exactly the supplied device.
    /// # Safety
    /// `device` must be a live ID3D11Device pointer created on this thread. All
    /// subsequent calls and destruction must remain on this thread.
    pub unsafe fn with_gpu_device(
        config: VideoConfig,
        limits: H264EncodingLimits,
        device: *mut c_void,
    ) -> io::Result<Self> {
        limits.validate_config(config)?;
        // SAFETY: delegated caller contract; the bridge takes its own reference.
        let inner = unsafe { Transform::new_gpu(config, device, limits.max_level_idc)? };
        Ok(Self {
            inner,
            scratch: vec![0; PACKET_BYTES],
            validator: H264Validator::with_limits(config.width, config.height, limits)?,
            parameters: Vec::new(),
            recovery_requested: Some(0),
            limits: Some(limits),
            config,
        })
    }
    /// # Safety
    /// `texture` is a live ID3D11Texture2D NV12 surface with the configured size
    /// on the exact device supplied at creation. It is borrowed only for this
    /// call; the bridge copies into a bounded tracked-sample pool before return.
    pub unsafe fn encode_texture(
        &mut self,
        texture: *mut c_void,
        pts: u64,
        force_keyframe: bool,
    ) -> io::Result<VideoEncodeStep> {
        if force_keyframe && self.recovery_requested.is_none() {
            self.recovery_requested = Some(pts);
        }
        // SAFETY: delegated caller contract; context/sample ownership stays native.
        let (accepted, output) = unsafe {
            self.inner.process_gpu(
                texture,
                pts,
                self.recovery_requested.is_some(),
                &mut self.scratch,
            )?
        };
        self.finish_step(accepted, output)
    }
    pub fn close(mut self) -> io::Result<()> {
        self.inner.close()
    }
    pub fn hardware(&self) -> bool {
        // SAFETY: thread-confined live transform; reads an observed output fact.
        unsafe { nl_mf_hardware_used(self.inner.handle.as_ptr()) != 0 }
    }
    pub fn encode(
        &mut self,
        bgra: &[u8],
        pts: u64,
        force_keyframe: bool,
    ) -> io::Result<Option<EncodedVideo>> {
        Ok(self.encode_step(bgra, pts, force_keyframe)?.output)
    }
    pub fn sps_info(&self) -> Option<H264SpsInfo> {
        self.validator.sps_info()
    }
    /// Backpressured input was not consumed and may be retried at the same PTS.
    /// Output can belong to an earlier accepted input. Only fatal errors poison
    /// the transform; delayed output never clears a pending recovery request.
    pub fn encode_step(
        &mut self,
        bgra: &[u8],
        pts: u64,
        force_keyframe: bool,
    ) -> io::Result<VideoEncodeStep> {
        if bgra.len() != self.inner.raw_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "H.264 BGRA geometry mismatch",
            ));
        }
        if force_keyframe && self.recovery_requested.is_none() {
            self.recovery_requested = Some(pts);
        }
        let (accepted, output) = self.inner.process(
            bgra,
            pts,
            self.recovery_requested.is_some(),
            &mut self.scratch,
        )?;
        self.finish_step(accepted, output)
    }
    fn finish_step(
        &mut self,
        accepted: bool,
        output: Option<(usize, u64)>,
    ) -> io::Result<VideoEncodeStep> {
        let Some((length, pts_90khz)) = output else {
            return Ok(VideoEncodeStep {
                accepted,
                output: None,
            });
        };
        let mut data = self.scratch[..length].to_vec();
        let nals = crate::h264::nals(&data)?;
        let keyframe = nals.iter().any(|nal| nal[0] & 31 == 5);
        let has_sps = nals.iter().any(|nal| nal[0] & 31 == 7);
        let has_pps = nals.iter().any(|nal| nal[0] & 31 == 8);
        if has_sps && has_pps {
            self.parameters.clear();
            for nal in nals.iter().filter(|nal| matches!(nal[0] & 31, 7 | 8)) {
                if nal.len() > 4096 || self.parameters.len() + nal.len() + 4 > 8192 {
                    return Err(io::Error::other("H.264 parameter set exceeds budget"));
                }
                self.parameters.extend_from_slice(&[0, 0, 0, 1]);
                self.parameters.extend_from_slice(nal);
            }
        }
        // Every recovery IDR is independently decodable after receiver reset.
        if keyframe && !(has_sps && has_pps) {
            let mut complete = self.parameters.clone();
            complete.extend_from_slice(&data);
            data = complete;
        }
        let unit = self.validator.validate(&data)?;
        if keyframe {
            // A new validator must accept every recovery IDR independently.
            H264Validator::new(self.config.width, self.config.height)?.validate(&data)?;
            if self
                .recovery_requested
                .is_some_and(|requested| pts_90khz >= requested)
            {
                self.recovery_requested = None;
            }
        }
        if let (Some(limits), Some(info)) = (self.limits, unit.sps) {
            limits.validate_sps(info)?;
            // A lower signalled level must also cover the actual target.
            H264EncodingLimits {
                max_level_idc: info.level_idc,
                ..limits
            }
            .validate_config(self.config)?;
        }
        Ok(VideoEncodeStep {
            accepted,
            output: Some(EncodedVideo {
                pts_90khz,
                keyframe,
                data,
            }),
        })
    }
    /// Collect delayed output without inventing or resubmitting input.
    pub fn drain_encoded(&mut self) -> io::Result<VideoEncodeStep> {
        let output = self.inner.receive(&mut self.scratch)?;
        self.finish_step(false, output)
    }
    pub fn set_bitrate(&mut self, kbps: u32) -> io::Result<()> {
        if self.inner.failed || !(64..=100_000).contains(&kbps) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid H.264 bitrate/context",
            ));
        }
        if let Some(limits) = self.limits {
            limits.validate_config(VideoConfig {
                bitrate_kbps: kbps,
                ..self.config
            })?;
        }
        if let Some(info) = self.sps_info() {
            H264EncodingLimits {
                max_level_idc: info.level_idc,
                require_constrained_baseline: false,
            }
            .validate_config(VideoConfig {
                bitrate_kbps: kbps,
                ..self.config
            })?;
        }
        // SAFETY: live, exclusively borrowed transform and bounded scalar.
        let code = unsafe { nl_mf_bitrate(self.inner.handle.as_ptr(), kbps) };
        if code < 0 {
            return Err(failed("bitrate update", code));
        }
        self.config.bitrate_kbps = kbps;
        Ok(())
    }
}
pub struct MfH264Decoder {
    inner: Transform,
    validator: H264Validator,
    queued: VecDeque<(zeroize::Zeroizing<Vec<u8>>, u64)>,
    queued_bytes: usize,
    last_queued: Option<u64>,
}

impl MfH264Decoder {
    /// Discard buffered output and reference state while retaining the owned
    /// transform/device. Input/output timestamp replay fences remain intact.
    pub fn reset_for_keyframe(&mut self) -> io::Result<()> {
        if self.inner.failed {
            return Err(io::Error::other("failed H.264 decoder cannot be reset"));
        }
        // SAFETY: exclusively borrowed live decoder on its owning COM thread.
        let code = unsafe { nl_mf_flush_decoder(self.inner.handle.as_ptr()) };
        if code < 0 {
            self.inner.failed = true;
            return Err(failed("decoder flush", code));
        }
        self.inner.timestamps.pending.clear();
        self.queued.clear();
        self.queued_bytes = 0;
        self.validator.reset_for_keyframe();
        Ok(())
    }
    pub fn new(width: u32, height: u32, hardware_only: bool) -> io::Result<Self> {
        Ok(Self {
            validator: H264Validator::new(width, height)?,
            queued: VecDeque::new(),
            queued_bytes: 0,
            last_queued: None,
            inner: Transform::new(
                VideoConfig {
                    width,
                    height,
                    fps: 60,
                    bitrate_kbps: 4_000,
                },
                false,
                hardware_only,
                0,
            )?,
        })
    }
    pub fn hardware(&self) -> bool {
        // SAFETY: thread-confined live transform; reads an observed output fact.
        unsafe { nl_mf_hardware_used(self.inner.handle.as_ptr()) != 0 }
    }
    /// Receive delayed output without resubmitting any compressed input.
    pub fn drain_frame(&mut self) -> io::Result<Option<(Vec<u8>, u64)>> {
        let mut output = vec![0; self.inner.raw_bytes];
        let frame = if let Some((packet, pts)) = self.queued.front() {
            let (accepted, frame) = self.inner.process(packet, *pts, false, &mut output)?;
            if accepted && let Some((packet, _)) = self.queued.pop_front() {
                self.queued_bytes -= packet.len();
            }
            frame
        } else {
            self.inner.receive(&mut output)?
        };
        if let Some((length, pts)) = frame {
            if length != output.len() {
                return Err(io::Error::other("H.264 decoded geometry mismatch"));
            }
            Ok(Some((output, pts)))
        } else {
            Ok(None)
        }
    }
    pub fn decode(&mut self, packet: &[u8], pts: u64) -> io::Result<Option<Vec<u8>>> {
        Ok(self.decode_frame(packet, pts)?.map(|(pixels, _)| pixels))
    }
    pub fn decode_frame(&mut self, packet: &[u8], pts: u64) -> io::Result<Option<(Vec<u8>, u64)>> {
        if packet.is_empty() || packet.len() > PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "H.264 packet exceeds budget",
            ));
        }
        if self.last_queued.is_some_and(|previous| pts <= previous) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stale H.264 packet timestamp",
            ));
        }
        // Decoder callers submit every network packet once. Retain unaccepted
        // input rather than silently losing a reference picture on backpressure.
        if self.queued.len() >= 8 || self.queued_bytes + packet.len() > 16 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "bounded H.264 decoder input queue is full",
            ));
        }
        self.validator.validate(packet)?;
        self.queued
            .push_back((zeroize::Zeroizing::new(packet.to_vec()), pts));
        self.queued_bytes += packet.len();
        self.last_queued = Some(pts);
        let mut output = vec![0; self.inner.raw_bytes];
        for _ in 0..4 {
            let Some((packet, pts)) = self.queued.front() else {
                break;
            };
            let (accepted, frame) = self.inner.process(packet, *pts, false, &mut output)?;
            if accepted && let Some((packet, _)) = self.queued.pop_front() {
                self.queued_bytes -= packet.len();
            }
            if let Some((length, pts)) = frame {
                if length != output.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "H.264 decoded geometry mismatch",
                    ));
                }
                return Ok(Some((output, pts)));
            }
            if !accepted {
                break;
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe extern "C" {
        fn nl_mf_backpressure_contract() -> u32;
    }
    #[test]
    fn not_accepting_drains_before_retry_and_never_resubmits_accepted_input() {
        // SAFETY: deterministic native pump self-test takes no pointers or
        // handles and never creates COM/MF resources.
        assert_eq!(unsafe { nl_mf_backpressure_contract() }, 15);
    }
    #[test]
    fn backpressure_keeps_input_retryable_and_preserves_delayed_output_pts() -> io::Result<()> {
        let mut timestamps = TimestampLedger::default();
        assert_eq!(timestamps.record(3, 100, 0, 1000, 0)?, (false, None));
        assert_eq!(timestamps.last_input, None);
        assert_eq!(timestamps.record(1, 100, 0, 1000, 0)?, (true, None));
        assert_eq!(
            timestamps.record(2, 200, 10, 1000, 100)?,
            (false, Some((10, 100)))
        );
        assert_eq!(timestamps.last_input, Some(100));
        assert_eq!(
            timestamps.record(0, 200, 10, 1000, 200)?,
            (true, Some((10, 200)))
        );
        assert!(timestamps.pending.is_empty());
        timestamps.record(1, 300, 0, 1000, 0)?;
        assert!(
            timestamps.record(2, 400, 10, 1000, 400).is_err(),
            "unaccepted PTS must never be relabelled as output"
        );
        Ok(())
    }
    #[test]
    fn hardware_target_produces_observed_independent_idr_or_reports_skip() -> io::Result<()> {
        let config = VideoConfig {
            width: 1280,
            height: 720,
            fps: 30,
            bitrate_kbps: 4000,
        };
        let mut encoder = match MfH264Encoder::new(config, true) {
            Ok(encoder) => encoder,
            Err(error) => {
                eprintln!("SKIP hardware H.264 target: no usable hardware MFT/GPU: {error}");
                return Ok(());
            }
        };
        let pixels = [32, 160, 64, 255].repeat((config.width * config.height) as usize);
        for frame in 0..32 {
            let step = encoder.encode_step(&pixels, frame * 3000, frame == 0)?;
            if let Some(packet) = step.output {
                assert!(packet.keyframe);
                assert!(
                    H264Validator::new(config.width, config.height)?
                        .validate(&packet.data)?
                        .keyframe
                );
                assert!(encoder.hardware());
                eprintln!(
                    "hardware H.264 actual SPS={} target=1280x720@30",
                    encoder
                        .sps_info()
                        .ok_or_else(|| io::Error::other("missing SPS"))?
                        .profile_level_id()
                );
                return Ok(());
            }
        }
        Err(io::Error::other(
            "hardware MFT opened but produced no bounded target output",
        ))
    }
    #[test]
    fn software_h264_roundtrip_recovery_idr_and_geometry_rejection() -> io::Result<()> {
        let config = VideoConfig {
            width: 320,
            height: 240,
            fps: 30,
            bitrate_kbps: 2_000,
        };
        software_roundtrip(config)
    }
    #[test]
    fn software_h264_actual_720p_target_roundtrip_and_recovery() -> io::Result<()> {
        software_roundtrip(VideoConfig {
            width: 1280,
            height: 720,
            fps: 30,
            bitrate_kbps: 4000,
        })
    }
    fn software_roundtrip(config: VideoConfig) -> io::Result<()> {
        let mut encoder = MfH264Encoder::with_limits(
            config,
            false,
            Some(H264EncodingLimits {
                max_level_idc: 31,
                require_constrained_baseline: false,
            }),
        )?;
        let pixels = [32, 160, 64, 255].repeat((config.width * config.height) as usize);
        let mut decoder = MfH264Decoder::new(config.width, config.height, false)?;
        let mut outputs = 0;
        let mut idrs = 0;
        let mut reset_pts = 0;
        for frame in 0..18 {
            let Some(packet) = encoder.encode(&pixels, frame * 3000, frame.is_multiple_of(6))?
            else {
                continue;
            };
            if packet.keyframe {
                idrs += 1;
                decoder.reset_for_keyframe()?;
                reset_pts = packet.pts_90khz;
                assert!(
                    MfH264Decoder::new(640, 480, false)?
                        .decode(&packet.data, packet.pts_90khz)
                        .is_err()
                );
            }
            if let Some((decoded, pts)) = decoder.decode_frame(&packet.data, packet.pts_90khz)? {
                outputs += 1;
                assert!(pts <= packet.pts_90khz);
                assert!(pts >= reset_pts, "pre-flush output escaped the decoder");
                assert!(
                    decoded
                        .chunks_exact(4)
                        .step_by(137)
                        .all(|pixel| (i32::from(pixel[1]) - 160).abs() < 20 && pixel[3] == 255)
                );
            }
        }
        assert!(outputs >= 12 && idrs >= 3, "outputs={outputs} idrs={idrs}");
        assert!(!encoder.hardware() && !decoder.hardware());
        let info = encoder
            .sps_info()
            .ok_or_else(|| io::Error::other("missing actual SPS"))?;
        assert_eq!(info.profile_idc, 66);
        assert!(info.level_idc <= 31);
        eprintln!(
            "software H.264 target={}x{}@{} kbps={} actual_sps={} encoded_outputs={outputs} recovery_idrs={idrs} encoder_hardware=false decoder_hardware=false",
            config.width,
            config.height,
            config.fps,
            config.bitrate_kbps,
            info.profile_level_id()
        );
        assert!(encoder.encode(&pixels, 1, false).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod gpu_input_tests {
    unsafe extern "C" {
        fn nl_mf_gpu_pool_contract() -> u32;
    }
    #[test]
    fn tracked_input_pool_reuses_only_released_slots_and_callback_outlives_owner() {
        // SAFETY: deterministic native pool/callback test, no OS GPU allocation.
        assert_eq!(unsafe { nl_mf_gpu_pool_contract() }, 1);
    }
}
