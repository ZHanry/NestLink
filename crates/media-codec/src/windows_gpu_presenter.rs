//! Windows WGL child surface and worker-confined hardware decoder/presenter.
//! No native pointer is serialized. Submitted means DXGI submission, not scanout.
#![allow(unsafe_code)]
use crate::H264Validator;
use std::{
    collections::VecDeque, ffi::c_void, io, marker::PhantomData, ptr::NonNull, rc::Rc, sync::Arc,
};

unsafe extern "C" {
    fn nl_gpu_surface_discover(key: u64, width: u32, height: u32, result: *mut *mut c_void) -> i32;
    fn nl_gpu_surface_place(
        surface: *mut c_void,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        visible: u32,
    ) -> i32;
    fn nl_gpu_surface_revoke(surface: *mut c_void);
    fn nl_gpu_surface_detach(surface: *mut c_void);
    fn nl_gpu_surface_deadline(surface: *mut c_void, deadline: u64);
    fn nl_gpu_probe_surface(width: u32, height: u32, result: *mut *mut c_void) -> i32;
    fn nl_gpu_surface_release(surface: *mut c_void);
    fn nl_gpu_open(
        surface: *mut c_void,
        width: u32,
        height: u32,
        fps: u32,
        result: *mut *mut c_void,
    ) -> i32;
    fn nl_gpu_step(
        handle: *mut c_void,
        input: *const u8,
        length: usize,
        pts: u64,
        due: u64,
        expires: u64,
        accepted: *mut u32,
        output_pts: *mut u64,
        qpc: *mut u64,
        submitted: *mut u32,
        converted: *mut u32,
    ) -> i32;
    fn nl_gpu_close(handle: *mut c_void);
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn QueryPerformanceCounter(value: *mut i64) -> i32;
    fn QueryPerformanceFrequency(value: *mut i64) -> i32;
}
/// Same-host monotonic counter and frequency; never a remote capture clock.
pub fn gpu_qpc() -> io::Result<(u64, u64)> {
    let mut count = 0i64;
    let mut frequency = 0i64;
    // SAFETY: Win32 writes one aligned initialized i64 to each output.
    if unsafe { QueryPerformanceCounter(&mut count) } == 0
        || unsafe { QueryPerformanceFrequency(&mut frequency) } == 0
        || count < 0
        || frequency <= 0
    {
        return Err(io::Error::other("QPC unavailable"));
    }
    Ok((count as u64, frequency as u64))
}
fn checked(code: i32) -> io::Result<()> {
    if code < 0 {
        Err(io::Error::other(format!(
            "GPU presenter failed ({code:#010x})"
        )))
    } else {
        Ok(())
    }
}
struct SurfaceInner(NonNull<c_void>);
// SAFETY: surface contains atomic lifetime/authority and HWND scalars, never COM.
// Native operations validate UI thread; revoke uses atomics on other threads.
unsafe impl Send for SurfaceInner {}
// SAFETY: see Send; window positioning is checked by the native bridge.
unsafe impl Sync for SurfaceInner {}
impl Drop for SurfaceInner {
    fn drop(&mut self) {
        // SAFETY: one native reference owned by this Arc, retained by subclass/worker.
        unsafe {
            nl_gpu_surface_revoke(self.0.as_ptr());
            nl_gpu_surface_release(self.0.as_ptr());
        }
    }
}
#[derive(Clone)]
pub struct GpuVideoSurface(Arc<SurfaceInner>);
impl GpuVideoSurface {
    /// Synthetic integration probe only: an owned NOACTIVATE WGL test window.
    /// Caller must detach on this same thread after presenter destruction.
    pub fn probe_window(width: u32, height: u32) -> io::Result<Self> {
        let mut handle = std::ptr::null_mut();
        // SAFETY: bounded native constructor with initialized out pointer.
        checked(unsafe { nl_gpu_probe_surface(width, height, &mut handle) })?;
        Ok(Self(Arc::new(SurfaceInner(
            NonNull::new(handle).ok_or_else(|| io::Error::other("null probe surface"))?,
        ))))
    }
    /// Call only inside the target viewport's glow PaintCallback. Non-WGL fails.
    pub fn discover(viewport_generation: u64, screen_size: [u32; 2]) -> io::Result<Self> {
        let mut handle = std::ptr::null_mut();
        // SAFETY: native discovery checks current WGL DC process/UI thread.
        checked(unsafe {
            nl_gpu_surface_discover(
                viewport_generation,
                screen_size[0],
                screen_size[1],
                &mut handle,
            )
        })?;
        Ok(Self(Arc::new(SurfaceInner(
            NonNull::new(handle).ok_or_else(|| io::Error::other("null GPU surface"))?,
        ))))
    }
    /// Window positioning is restricted to the creating UI thread.
    pub fn place(&self, x: i32, y: i32, width: u32, height: u32, visible: bool) -> io::Result<()> {
        // SAFETY: owned live token; native bridge rejects wrong thread/dead HWND.
        checked(unsafe {
            nl_gpu_surface_place(self.0.0.as_ptr(), x, y, width, height, visible.into())
        })
    }
    /// Immediately hides on UI thread; other threads invalidate submission authority.
    pub fn revoke(&self) {
        // SAFETY: native token lifetime is retained by this Arc.
        unsafe {
            nl_gpu_surface_revoke(self.0.0.as_ptr());
        }
    }
    /// Terminal UI-thread operation, after revocation; safe to repeat.
    pub fn detach(&self) {
        // SAFETY: native token validates UI owner thread and atomically fences workers.
        unsafe {
            nl_gpu_surface_detach(self.0.0.as_ptr());
        }
    }
    pub fn set_authority_deadline(&self, deadline_qpc: u64) {
        // SAFETY: atomic scalar update on the retained lifetime token.
        unsafe {
            nl_gpu_surface_deadline(self.0.0.as_ptr(), deadline_qpc);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GpuDecodedPicture {
    pub sequence: u64,
    pub pts_90khz: u64,
    pub submitted_qpc: Option<u64>,
    pub gpu_converted: bool,
}
#[derive(Debug, Clone, Copy)]
pub struct GpuDecodeStep {
    pub accepted: bool,
    /// Actual MF output receipt, emitted once before scheduled presentation.
    pub decoded: Option<(u64, u64)>,
    pub picture: Option<GpuDecodedPicture>,
}
pub struct GpuH264Presenter {
    handle: NonNull<c_void>,
    validator: H264Validator,
    pending: VecDeque<(u64, u64)>,
    ready_identity: VecDeque<(u64, u64)>,
    last_input: Option<u64>,
    last_sequence: Option<u64>,
    failed: bool,
    _thread: PhantomData<Rc<()>>,
}
impl GpuH264Presenter {
    pub fn new(surface: &GpuVideoSurface, width: u32, height: u32, fps: u32) -> io::Result<Self> {
        let validator = H264Validator::new_sdr(width, height)?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: bridge borrows surface and retains its own native reference.
        checked(unsafe { nl_gpu_open(surface.0.0.as_ptr(), width, height, fps, &mut handle) })?;
        Ok(Self {
            handle: NonNull::new(handle).ok_or_else(|| io::Error::other("null GPU presenter"))?,
            validator,
            pending: VecDeque::new(),
            ready_identity: VecDeque::new(),
            last_input: None,
            last_sequence: None,
            failed: false,
            _thread: PhantomData,
        })
    }
    pub fn submit(
        &mut self,
        sequence: u64,
        pts_90khz: u64,
        bytes: &[u8],
    ) -> io::Result<GpuDecodeStep> {
        self.submit_scheduled(sequence, pts_90khz, bytes, 0, 0)
    }
    pub fn submit_scheduled(
        &mut self,
        sequence: u64,
        pts_90khz: u64,
        bytes: &[u8],
        due_qpc: u64,
        not_after_qpc: u64,
    ) -> io::Result<GpuDecodeStep> {
        if self.pending.len() >= 8 {
            return self.poll();
        }
        if self.failed
            || self.last_input.is_some_and(|v| pts_90khz <= v)
            || self.last_sequence.is_some_and(|v| sequence <= v)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stale/failed GPU decoder input",
            ));
        }
        // Validator mutation before NOTACCEPTING retry is safe: repeat identical AU.
        self.validator.validate(bytes)?;
        if not_after_qpc != 0 && due_qpc > not_after_qpc {
            return Err(io::Error::other("invalid GPU playout interval"));
        }
        self.exchange(sequence, pts_90khz, bytes, due_qpc, not_after_qpc)
    }
    pub fn poll(&mut self) -> io::Result<GpuDecodeStep> {
        self.exchange(0, 0, &[], 0, 0)
    }
    fn exchange(
        &mut self,
        sequence: u64,
        pts: u64,
        bytes: &[u8],
        due: u64,
        expires: u64,
    ) -> io::Result<GpuDecodeStep> {
        if self.failed {
            return Err(io::Error::other("failed GPU decoder"));
        }
        let mut accepted = 0;
        let mut actual_pts = 0;
        let mut qpc = 0;
        let mut submitted = 0;
        let mut converted = 0;
        // SAFETY: owned thread-confined context; bounded validated input and initialized outputs.
        let code = unsafe {
            nl_gpu_step(
                self.handle.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                pts,
                due,
                expires,
                &mut accepted,
                &mut actual_pts,
                &mut qpc,
                &mut submitted,
                &mut converted,
            )
        };
        if code < 0 {
            self.failed = true;
            checked(code)?;
        }
        if accepted != 0 {
            self.pending.push_back((sequence, pts));
            self.last_input = Some(pts);
            self.last_sequence = Some(sequence);
        }
        let decoded = if code == 2 {
            let Some((sequence, expected)) = self.pending.pop_front() else {
                self.failed = true;
                return Err(io::Error::other(
                    "GPU decoder output without accepted input",
                ));
            };
            if expected != actual_pts {
                self.failed = true;
                return Err(io::Error::other("GPU decoder actual PTS mismatch"));
            }
            self.ready_identity.push_back((sequence, actual_pts));
            Some((sequence, actual_pts))
        } else {
            None
        };
        let picture = if code == 0 {
            let Some((sequence, expected)) = self.ready_identity.pop_front() else {
                self.failed = true;
                return Err(io::Error::other("GPU presentation without output receipt"));
            };
            if expected != actual_pts {
                self.failed = true;
                return Err(io::Error::other("GPU presentation PTS mismatch"));
            }
            Some(GpuDecodedPicture {
                sequence,
                pts_90khz: actual_pts,
                submitted_qpc: (submitted != 0).then_some(qpc),
                gpu_converted: converted != 0,
            })
        } else {
            None
        };
        Ok(GpuDecodeStep {
            accepted: accepted != 0,
            decoded,
            picture,
        })
    }
}
impl Drop for GpuH264Presenter {
    fn drop(&mut self) {
        // SAFETY: !Send/!Sync guarantees destruction on the creating COM worker.
        unsafe {
            nl_gpu_close(self.handle.as_ptr());
        }
    }
}
