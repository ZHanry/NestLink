//! Explicit libvpx VP9 profile 1, eight-bit, full-range sRGB 4:4:4.
//! Each access unit is an independent visible keyframe. This is lossy RGB;
//! no chroma plane is subsampled and no YUV matrix conversion is performed.
#![allow(unsafe_code)]
use crate::{EncodedVideo, VideoConfig, vp8::{PacketSink, packet_callback}};
use std::{ffi::c_void, io, ptr::NonNull};
use zeroize::Zeroizing;

const RAW_BYTES: u64 = 64 * 1024 * 1024;
const PACKET_BYTES: usize = 8 * 1024 * 1024;
type Callback = unsafe extern "C" fn(*mut c_void, *const u8, usize, u64, u32) -> i32;
unsafe extern "C" {
    fn nl_vp9_peek(packet: *const u8, length: usize, width: u32, height: u32) -> i32;
    fn nl_vp9_encoder_create(width: u32, height: u32, fps: u32, kbps: u32, out: *mut *mut c_void) -> i32;
    fn nl_vp9_encode(handle: *mut c_void, bgra: *const u8, length: usize, pts: u64, callback: Callback, user: *mut c_void) -> i32;
    fn nl_vp9_encoder_close(handle: *mut c_void) -> i32;
    fn nl_vp9_decoder_create(width: u32, height: u32, out: *mut *mut c_void) -> i32;
    fn nl_vp9_decode(handle: *mut c_void, packet: *const u8, length: usize, bgra: *mut u8, bytes: usize) -> i32;
    fn nl_vp9_decoder_close(handle: *mut c_void) -> i32;
}
fn failure(action: &str, code: i32) -> io::Error {
    let kind = match code {
        1 => io::ErrorKind::InvalidData,
        2 => io::ErrorKind::OutOfMemory,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("VP9 RGB444 {action} failed (bridge status {code})"))
}
pub(crate) fn validate_config(config: VideoConfig) -> io::Result<usize> {
    let bytes = geometry(config.width, config.height)?;
    if !(1..=144).contains(&config.fps) || !(64..=100_000).contains(&config.bitrate_kbps) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "VP9 RGB444 timing or bitrate exceeds budget"));
    }
    Ok(bytes)
}
fn geometry(width: u32, height: u32) -> io::Result<usize> {
    let bytes = u64::from(width) * u64::from(height) * 4;
    if !(16..=8192).contains(&width) || !(16..=8192).contains(&height) || bytes > RAW_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "VP9 RGB444 geometry exceeds budget"));
    }
    Ok(bytes as usize)
}
/// The fixed libvpx public parser must identify one independent keyframe with
/// exact geometry. Actual profile/color/depth/4:4:4 are checked on decoded output.
pub fn validate_vp9_rgb444_keyframe(packet: &[u8], width: u32, height: u32) -> io::Result<()> {
    geometry(width, height)?;
    if packet.is_empty() || packet.len() > PACKET_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "VP9 packet exceeds budget"));
    }
    // SAFETY: the public parser borrows only this checked packet span.
    let code = unsafe { nl_vp9_peek(packet.as_ptr(), packet.len(), width, height) };
    if code != 0 { return Err(failure("keyframe admission", code)); }
    Ok(())
}

pub struct Vp9Rgb444Encoder {
    handle: Option<NonNull<c_void>>,
    config: VideoConfig,
    resource_id: [u8; 16],
    last_pts: Option<u64>,
    failed: bool,
}
// SAFETY: one context owner, with all native operations requiring &mut self.
unsafe impl Send for Vp9Rgb444Encoder {}
impl Vp9Rgb444Encoder {
    pub fn new(config: VideoConfig) -> io::Result<Self> {
        validate_config(config)?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: scalar config and valid out pointer; success transfers one owner.
        let code = unsafe { nl_vp9_encoder_create(config.width, config.height, config.fps, config.bitrate_kbps, &mut handle) };
        if code != 0 { return Err(failure("encoder initialization", code)); }
        let handle = NonNull::new(handle).ok_or_else(|| io::Error::other("VP9 encoder returned no owner"))?;
        Ok(Self { handle: Some(handle), config, resource_id: *uuid::Uuid::new_v4().as_bytes(), last_pts: None, failed: false })
    }
    pub(crate) fn resource_id(&self) -> io::Result<[u8; 16]> {
        if self.handle.is_none() || self.failed { return Err(io::Error::other("VP9 encoder retired")); }
        Ok(self.resource_id)
    }
    pub fn encode(&mut self, bgra: &[u8], pts: u64) -> io::Result<EncodedVideo> {
        self.resource_id()?;
        if bgra.len() != geometry(self.config.width, self.config.height)?
            || pts > i64::MAX as u64 || self.last_pts.is_some_and(|last| pts <= last) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "VP9 RGB444 input geometry or PTS differs"));
        }
        let handle = self.handle.ok_or_else(|| io::Error::other("VP9 encoder closed"))?;
        let mut sink = PacketSink { pts, packet: None, error: None };
        // SAFETY: exclusively owned context; C synchronously borrows the frame,
        // callback and stack sink. The shared callback copies its bounded packet.
        let code = unsafe { nl_vp9_encode(handle.as_ptr(), bgra.as_ptr(), bgra.len(), pts, packet_callback, (&mut sink as *mut PacketSink).cast()) };
        if code != 0 || sink.error.is_some() || !sink.packet.as_ref().is_some_and(|packet| packet.keyframe) {
            self.failed = true;
            return Err(sink.error.unwrap_or_else(|| failure("encoding", code)));
        }
        self.last_pts = Some(pts);
        sink.packet.ok_or_else(|| io::Error::other("VP9 encoder produced no keyframe"))
    }
    pub fn close(mut self) -> io::Result<()> {
        let result = self.checked_close();
        if result.is_err() { std::mem::forget(self); }
        result
    }
    fn checked_close(&mut self) -> io::Result<()> {
        let Some(handle) = self.handle else { return Ok(()); };
        self.failed = true;
        // SAFETY: unique owner with no active codec call; C retains state on error.
        let code = unsafe { nl_vp9_encoder_close(handle.as_ptr()) };
        if code != 0 { return Err(failure("checked encoder close", code)); }
        self.handle = None;
        Ok(())
    }
}
impl Drop for Vp9Rgb444Encoder { fn drop(&mut self) { let _ = self.checked_close(); } }

pub struct Vp9Rgb444Decoder {
    handle: Option<NonNull<c_void>>,
    width: u32,
    height: u32,
    resource_id: [u8; 16],
    failed: bool,
}
// SAFETY: a native context has one owner and every call requires &mut self.
unsafe impl Send for Vp9Rgb444Decoder {}
impl Vp9Rgb444Decoder {
    pub fn new(width: u32, height: u32) -> io::Result<Self> {
        geometry(width, height)?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: checked scalar geometry and one valid out pointer.
        let code = unsafe { nl_vp9_decoder_create(width, height, &mut handle) };
        if code != 0 { return Err(failure("decoder initialization", code)); }
        let handle = NonNull::new(handle).ok_or_else(|| io::Error::other("VP9 decoder returned no owner"))?;
        Ok(Self { handle: Some(handle), width, height, resource_id: *uuid::Uuid::new_v4().as_bytes(), failed: false })
    }
    pub(crate) fn resource_id(&self) -> io::Result<[u8; 16]> {
        if self.handle.is_none() || self.failed { return Err(io::Error::other("VP9 decoder retired")); }
        Ok(self.resource_id)
    }
    pub fn decode(&mut self, packet: &[u8]) -> io::Result<Vec<u8>> {
        self.resource_id()?;
        validate_vp9_rgb444_keyframe(packet, self.width, self.height)?;
        let bytes = geometry(self.width, self.height)?;
        let mut pixels = Zeroizing::new(Vec::new());
        pixels.try_reserve_exact(bytes).map_err(io::Error::other)?;
        pixels.resize(bytes, 0);
        let handle = self.handle.ok_or_else(|| io::Error::other("VP9 decoder closed"))?;
        // SAFETY: C borrows this packet and exact writable BGRA span. It checks
        // the actual decoded format/color/depth/strides before converting.
        let code = unsafe { nl_vp9_decode(handle.as_ptr(), packet.as_ptr(), packet.len(), pixels.as_mut_ptr(), pixels.len()) };
        if code != 0 { self.failed = true; return Err(failure("decoding", code)); }
        Ok(std::mem::take(&mut *pixels))
    }
    pub fn close(mut self) -> io::Result<()> {
        let result = self.checked_close();
        if result.is_err() { std::mem::forget(self); }
        result
    }
    fn checked_close(&mut self) -> io::Result<()> {
        let Some(handle) = self.handle else { return Ok(()); };
        self.failed = true;
        // SAFETY: unique owner with no native call active; error retains state.
        let code = unsafe { nl_vp9_decoder_close(handle.as_ptr()) };
        if code != 0 { return Err(failure("checked decoder close", code)); }
        self.handle = None;
        Ok(())
    }
}
impl Drop for Vp9Rgb444Decoder { fn drop(&mut self) { let _ = self.checked_close(); } }
