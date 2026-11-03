//! Same-thread AMF hardware transform. Native driver calls remain on the
//! original worker; checked-close failures retain the native state/module.
#![allow(unsafe_code)]
use crate::{HevcMain8Contract, OwnerObservation, VideoConfig};
use std::{collections::VecDeque, ffi::c_void, io, marker::PhantomData, ptr::NonNull, rc::Rc};

unsafe extern "C" {
    fn nl_amf_open(
        device: *mut c_void,
        width: u32,
        height: u32,
        fps: u32,
        kbps: u32,
        depth: u32,
        result: *mut *mut c_void,
    ) -> i32;
    fn nl_amf_process(
        handle: *mut c_void,
        texture: *mut c_void,
        pts: u64,
        keyframe: u32,
        output: *mut u8,
        capacity: usize,
        written: *mut usize,
        output_pts: *mut u64,
    ) -> i32;
    fn nl_amf_drain(handle: *mut c_void) -> i32;
    fn nl_amf_observation(
        handle: *mut c_void,
        out: *mut crate::owner_observation::RawOwnerObservation,
        runtime: *mut u64,
        flags: *mut u32,
    ) -> i32;
    fn nl_amf_close(handle: *mut c_void) -> i32;
}
fn checked(code: i32, stage: &str) -> io::Result<()> {
    if code < 0 {
        Err(io::Error::other(format!(
            "AMD AMF {stage} failed ({code:#010x}); no fallback"
        )))
    } else {
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Observation {
    pub owner: OwnerObservation,
    pub runtime: u64,
    pub gpu_input: bool,
    pub drain_started: bool,
    pub drain_complete: bool,
}
pub(crate) struct Transform {
    handle: NonNull<c_void>,
    pending: VecDeque<u64>,
    last_input: Option<u64>,
    last_output: Option<u64>,
    failed: bool,
    closed: bool,
    draining: bool,
    _thread: PhantomData<Rc<()>>,
}
impl Transform {
    /// The original creating-thread device stays retained by the native owner.
    pub(crate) unsafe fn new(
        config: VideoConfig,
        device: *mut c_void,
        depth: u8,
    ) -> io::Result<Self> {
        match depth {
            8 => HevcMain8Contract::validate_config(config)?,
            10 => HevcMain8Contract::validate_main10_config(config)?,
            _ => return Err(io::Error::other("AMF exact bit depth unavailable")),
        }
        let mut handle = std::ptr::null_mut();
        // SAFETY: original live owner-thread device, initialized output, bounded config.
        checked(
            unsafe {
                nl_amf_open(
                    device,
                    config.width,
                    config.height,
                    config.fps,
                    config.bitrate_kbps,
                    depth.into(),
                    &mut handle,
                )
            },
            "open",
        )?;
        Ok(Self {
            handle: NonNull::new(handle).ok_or_else(|| io::Error::other("null AMF owner"))?,
            pending: VecDeque::new(),
            last_input: None,
            last_output: None,
            failed: false,
            closed: false,
            draining: false,
            _thread: PhantomData,
        })
    }
    fn current(&self) -> io::Result<()> {
        if self.failed || self.closed {
            Err(io::Error::other("AMF owner failed or closed"))
        } else {
            Ok(())
        }
    }
    pub(crate) fn observation(&self) -> io::Result<Observation> {
        self.current()?;
        let mut raw = crate::owner_observation::RawOwnerObservation::default();
        let (mut runtime, mut flags) = (0, 0);
        // SAFETY: original live native handle on its creating thread; initialized outputs.
        checked(
            unsafe { nl_amf_observation(self.handle.as_ptr(), &mut raw, &mut runtime, &mut flags) },
            "observation",
        )?;
        if flags & !7 != 0 || flags & 1 == 0 || runtime == 0 || flags & 4 != 0 && flags & 2 == 0 {
            return Err(io::Error::other("invalid AMF backend observation"));
        }
        Ok(Observation {
            owner: raw.try_into()?,
            runtime,
            gpu_input: flags & 1 != 0,
            drain_started: flags & 2 != 0,
            drain_complete: flags & 4 != 0,
        })
    }
    pub(crate) unsafe fn process_gpu(
        &mut self,
        texture: *mut c_void,
        pts: u64,
        keyframe: bool,
        output: &mut [u8],
    ) -> io::Result<(bool, Option<(usize, u64)>)> {
        self.current()?;
        if texture.is_null() || self.draining || self.last_input.is_some_and(|last| pts <= last) {
            return Err(io::Error::other("AMF stale/null input or draining owner"));
        }
        // SAFETY: caller's exact same-device texture stays valid for this synchronous copy.
        unsafe { self.exchange(texture, pts, keyframe, output) }
    }
    pub(crate) fn receive(&mut self, output: &mut [u8]) -> io::Result<Option<(usize, u64)>> {
        self.current()?;
        // SAFETY: null texture explicitly polls without submitting any input.
        let (accepted, value) = unsafe { self.exchange(std::ptr::null_mut(), 0, false, output) }?;
        if accepted {
            self.failed = true;
            return Err(io::Error::other("AMF poll unexpectedly accepted input"));
        }
        Ok(value)
    }
    unsafe fn exchange(
        &mut self,
        texture: *mut c_void,
        pts: u64,
        keyframe: bool,
        output: &mut [u8],
    ) -> io::Result<(bool, Option<(usize, u64)>)> {
        let (mut written, mut output_pts) = (0, 0);
        // SAFETY: original native owner, borrowed texture contract, writable bounded slice.
        let code = unsafe {
            nl_amf_process(
                self.handle.as_ptr(),
                texture,
                pts,
                keyframe.into(),
                output.as_mut_ptr(),
                output.len(),
                &mut written,
                &mut output_pts,
            )
        };
        let result = (|| {
            checked(code, "process")?;
            if !(0..=3).contains(&code) {
                return Err(io::Error::other("invalid AMF progress status"));
            }
            let accepted = code <= 1;
            let value = if code == 1 || code == 3 {
                if written != 0 {
                    return Err(io::Error::other("AMF unexpected output metadata"));
                }
                None
            } else {
                if written == 0
                    || written > output.len()
                    || written > 8 * 1024 * 1024
                    || self.pending.front() != Some(&output_pts)
                    || self.last_output.is_some_and(|last| output_pts <= last)
                {
                    return Err(io::Error::other(
                        "AMF output differs from original size/PTS ledger",
                    ));
                }
                self.pending.pop_front();
                self.last_output = Some(output_pts);
                Some((written, output_pts))
            };
            // Native always queries old output before submitting a new input.
            // Retire that output first so simultaneous progress preserves the
            // same sixteen-entry bound without accepting a seventeenth frame.
            if accepted {
                if texture.is_null() || self.pending.len() >= 16 {
                    return Err(io::Error::other("AMF acceptance exceeds original ledger"));
                }
                self.last_input = Some(pts);
                self.pending.push_back(pts);
            }
            Ok((accepted, value))
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub(crate) fn begin_hevc_drain(&mut self) -> io::Result<()> {
        self.current()?;
        if self.draining {
            return Err(io::Error::other("AMF already draining"));
        }
        // SAFETY: original live owner-thread handle, exactly one drain transition.
        let code = unsafe { nl_amf_drain(self.handle.as_ptr()) };
        if code < 0 {
            self.failed = true;
        }
        checked(code, "drain")?;
        self.draining = true;
        Ok(())
    }
    pub(crate) fn pending_frames(&self) -> usize {
        self.pending.len()
    }
    pub(crate) fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        // SAFETY: consuming same-thread close; failed native close retains all resources.
        checked(
            unsafe { nl_amf_close(self.handle.as_ptr()) },
            "checked close (unknown cleanup quarantines owner)",
        )
    }
}
impl Drop for Transform {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("{error}");
        }
    }
}

#[cfg(test)]
mod boundary_tests {
    #[test]
    fn original_native_range_types_release_flags_and_null_device_are_strict() {
        unsafe extern "C" {
            fn nl_amf_boundary_contract() -> u32;
        }
        // SAFETY: bounded scalar/callback test; no runtime/device or pixels.
        assert_eq!(unsafe { nl_amf_boundary_contract() }, 127);
    }

    #[test]
    fn optional_legacy_properties_require_complete_consistent_absence() {
        unsafe extern "C" {
            fn nl_amf_optional_property_contract() -> u32;
        }
        // SAFETY: production descriptor decisions with scalar API responses;
        // no installed runtime, device, pixel submission or hardware claim.
        assert_eq!(unsafe { nl_amf_optional_property_contract() }, 524287);
    }
}
