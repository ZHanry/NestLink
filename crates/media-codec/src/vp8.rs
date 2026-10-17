//! A bounded VP8 software baseline. Call from a dedicated media worker.
//! This codec neither owns nor grants session/OS permission.
#![allow(unsafe_code)]
use std::{ffi::c_void, io, ptr::NonNull};
use zeroize::Zeroizing;

const RAW_BYTES: usize = 64 * 1024 * 1024;
const PACKET_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct VideoConfig {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
}
#[derive(Debug)]
pub struct EncodedVideo {
    pub pts_90khz: u64,
    pub keyframe: bool,
    pub data: Vec<u8>,
}
type PacketCallback = unsafe extern "C" fn(*mut c_void, *const u8, usize, u64, u32) -> i32;
unsafe extern "C" {
    fn nl_vp8_encoder_create(
        width: u32,
        height: u32,
        fps: u32,
        bitrate_kbps: u32,
        out: *mut *mut c_void,
    ) -> i32;
    fn nl_vp8_encoder_destroy(handle: *mut c_void);
    fn nl_vp8_encoder_set_bitrate(handle: *mut c_void, bitrate_kbps: u32) -> i32;
    fn nl_vp8_encode(
        handle: *mut c_void,
        data: *const u8,
        length: usize,
        pts: u64,
        force_keyframe: u32,
        callback: PacketCallback,
        user: *mut c_void,
    ) -> i32;
    fn nl_vp8_decoder_create(width: u32, height: u32, out: *mut *mut c_void) -> i32;
    fn nl_vp8_decoder_destroy(handle: *mut c_void);
    fn nl_vp8_decode(
        handle: *mut c_void,
        packet: *const u8,
        length: usize,
        output: *mut u8,
        output_length: usize,
    ) -> i32;
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn geometry(width: u32, height: u32) -> io::Result<(usize, usize)> {
    let pixels = u64::from(width) * u64::from(height);
    if width == 0 || height == 0 || width > 8192 || height > 8192 || pixels * 4 > RAW_BYTES as u64 {
        return Err(invalid("VP8 dimensions exceed raw frame budget"));
    }
    let chroma = u64::from(width.div_ceil(2)) * u64::from(height.div_ceil(2));
    Ok(((pixels * 4) as usize, (pixels + chroma * 2) as usize))
}
fn bytes(length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(io::Error::other)?;
    bytes.resize(length, 0);
    Ok(bytes)
}
fn bridge_error(action: &str, code: i32) -> io::Error {
    let kind = match code {
        1 => io::ErrorKind::InvalidData,
        2 => io::ErrorKind::OutOfMemory,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("VP8 {action} failed (bridge status {code})"))
}
struct PacketSink {
    pts: u64,
    packet: Option<EncodedVideo>,
    error: Option<io::Error>,
}
unsafe extern "C" fn packet_callback(
    user: *mut c_void,
    data: *const u8,
    length: usize,
    pts: u64,
    keyframe: u32,
) -> i32 {
    // SAFETY: encode exclusively borrows this stack sink for this synchronous call.
    let sink = unsafe { &mut *user.cast::<PacketSink>() };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if data.is_null()
            || length == 0
            || length > PACKET_BYTES
            || pts != sink.pts
            || keyframe > 1
            || sink.packet.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid VP8 output packet",
            ));
        }
        // SAFETY: the C bridge invokes us before its next libvpx call, while
        // libvpx guarantees that this checked packet span remains available.
        let source = unsafe { std::slice::from_raw_parts(data, length) };
        let mut data = Vec::new();
        data.try_reserve_exact(length).map_err(io::Error::other)?;
        data.extend_from_slice(source);
        sink.packet = Some(EncodedVideo {
            pts_90khz: pts,
            keyframe: keyframe != 0,
            data,
        });
        Ok(())
    }))
    .unwrap_or_else(|_| Err(io::Error::other("VP8 output callback panicked")));
    if let Err(error) = result {
        sink.error = Some(error);
        1
    } else {
        0
    }
}

pub struct Vp8Encoder {
    handle: NonNull<c_void>,
    config: VideoConfig,
    last_pts: Option<u64>,
    failed: bool,
}
// SAFETY: a context has a single owner. Every codec operation requires &mut
// self; moving it to its dedicated worker never permits concurrent C access.
unsafe impl Send for Vp8Encoder {}
impl Vp8Encoder {
    pub fn new(config: VideoConfig) -> io::Result<Self> {
        geometry(config.width, config.height)?;
        if !(1..=120).contains(&config.fps) || !(64..=100_000).contains(&config.bitrate_kbps) {
            return Err(invalid(
                "VP8 frame rate or bitrate exceeds supported bounds",
            ));
        }
        let mut handle = std::ptr::null_mut();
        // SAFETY: scalar configuration and a valid out pointer. On success the
        // returned context has one Rust owner, released by Drop.
        let code = unsafe {
            nl_vp8_encoder_create(
                config.width,
                config.height,
                config.fps,
                config.bitrate_kbps,
                &mut handle,
            )
        };
        if code != 0 {
            return Err(bridge_error("encoder initialization", code));
        }
        let handle = NonNull::new(handle)
            .ok_or_else(|| io::Error::other("VP8 encoder returned no context"))?;
        Ok(Self {
            handle,
            config,
            last_pts: None,
            failed: false,
        })
    }
    /// Reconfigure this context on its owning worker without resetting frame
    /// references, presentation timestamps, geometry or the keyframe history.
    pub fn set_bitrate(&mut self, bitrate_kbps: u32) -> io::Result<()> {
        if !(64..=100_000).contains(&bitrate_kbps) {
            return Err(invalid("VP8 bitrate exceeds supported bounds"));
        }
        if self.failed {
            return Err(io::Error::other(
                "VP8 encoder failed; create a fresh context",
            ));
        }
        if self.config.bitrate_kbps == bitrate_kbps {
            return Ok(());
        }
        // SAFETY: this is the same uniquely owned context as encode. The C
        // bridge copies and checks the scalar configuration synchronously.
        let code = unsafe { nl_vp8_encoder_set_bitrate(self.handle.as_ptr(), bitrate_kbps) };
        if code != 0 {
            self.failed = true;
            return Err(bridge_error("bitrate reconfiguration", code));
        }
        self.config.bitrate_kbps = bitrate_kbps;
        Ok(())
    }

    pub fn encode(
        &mut self,
        bgra: &[u8],
        pts_90khz: u64,
        force_keyframe: bool,
    ) -> io::Result<EncodedVideo> {
        if self.failed {
            return Err(io::Error::other(
                "VP8 encoder failed; create a fresh context",
            ));
        }
        if pts_90khz > i64::MAX as u64 || self.last_pts.is_some_and(|last| pts_90khz <= last) {
            return Err(invalid(
                "VP8 timestamps must increase within signed 64-bit range",
            ));
        }
        let i420 = Zeroizing::new(bgra_to_i420(self.config.width, self.config.height, bgra)?);
        let mut sink = PacketSink {
            pts: pts_90khz,
            packet: None,
            error: None,
        };
        // SAFETY: this uniquely owned context and both buffers live throughout
        // the synchronous bridge call; neither borrowed pointer is retained.
        let code = unsafe {
            nl_vp8_encode(
                self.handle.as_ptr(),
                i420.as_ptr(),
                i420.len(),
                pts_90khz,
                u32::from(force_keyframe),
                packet_callback,
                (&mut sink as *mut PacketSink).cast(),
            )
        };
        if code != 0 || sink.error.is_some() || sink.packet.is_none() {
            self.failed = true;
            return Err(sink.error.unwrap_or_else(|| bridge_error("encoding", code)));
        }
        let packet = sink
            .packet
            .ok_or_else(|| io::Error::other("VP8 encoder produced no frame"))?;
        if (self.last_pts.is_none() || force_keyframe) && !packet.keyframe {
            self.failed = true;
            return Err(io::Error::other(
                "VP8 encoder did not supply the required keyframe",
            ));
        }
        self.last_pts = Some(pts_90khz);
        Ok(packet)
    }
}
impl Drop for Vp8Encoder {
    fn drop(&mut self) {
        // SAFETY: this is the unique context owner and no codec call is active.
        unsafe { nl_vp8_encoder_destroy(self.handle.as_ptr()) };
    }
}
pub struct Vp8Decoder {
    handle: NonNull<c_void>,
    width: u32,
    height: u32,
    failed: bool,
}
// SAFETY: the context moves as a single owner and is only used through &mut self.
unsafe impl Send for Vp8Decoder {}
impl Vp8Decoder {
    pub fn new(width: u32, height: u32) -> io::Result<Self> {
        geometry(width, height)?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: valid scalar geometry and out pointer; Drop owns successful handles.
        let code = unsafe { nl_vp8_decoder_create(width, height, &mut handle) };
        if code != 0 {
            return Err(bridge_error("decoder initialization", code));
        }
        let handle = NonNull::new(handle)
            .ok_or_else(|| io::Error::other("VP8 decoder returned no context"))?;
        Ok(Self {
            handle,
            width,
            height,
            failed: false,
        })
    }
    pub fn decode(&mut self, packet: &[u8]) -> io::Result<Vec<u8>> {
        if self.failed {
            return Err(io::Error::other(
                "VP8 decoder failed; await a keyframe in a fresh context",
            ));
        }
        if packet.len() < 3 || packet.len() > PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VP8 packet exceeds encoded frame budget",
            ));
        }
        let (_, length) = geometry(self.width, self.height)?;
        let mut i420 = Zeroizing::new(bytes(length)?);
        // SAFETY: C borrows this immutable packet and the exact writable I420
        // span for this call. It validates keyframe dimensions before decoding.
        let code = unsafe {
            nl_vp8_decode(
                self.handle.as_ptr(),
                packet.as_ptr(),
                packet.len(),
                i420.as_mut_ptr(),
                i420.len(),
            )
        };
        if code != 0 {
            self.failed = true;
            return Err(bridge_error("decoding", code));
        }
        i420_to_bgra(self.width, self.height, &i420)
    }
}
impl Drop for Vp8Decoder {
    fn drop(&mut self) {
        // SAFETY: uniquely owned context with no concurrent codec operation.
        unsafe { nl_vp8_decoder_destroy(self.handle.as_ptr()) };
    }
}

fn bgra_to_i420(width: u32, height: u32, bgra: &[u8]) -> io::Result<Vec<u8>> {
    let (raw, packed) = geometry(width, height)?;
    if bgra.len() != raw {
        return Err(invalid("BGRA frame length does not match VP8 geometry"));
    }
    let (w, h) = (width as usize, height as usize);
    let cw = w.div_ceil(2);
    let chroma = cw * h.div_ceil(2);
    let mut output = bytes(packed)?;
    // BT.601 studio-range integer matrix. Alpha is not a VP8 component.
    for (index, pixel) in bgra.chunks_exact(4).enumerate() {
        let (b, g, r) = (
            i32::from(pixel[0]),
            i32::from(pixel[1]),
            i32::from(pixel[2]),
        );
        output[index] = (((66 * r + 129 * g + 25 * b + 128) >> 8) + 16) as u8;
    }
    for y in (0..h).step_by(2) {
        for x in (0..w).step_by(2) {
            let (mut r, mut g, mut b, mut count) = (0, 0, 0, 0);
            for row in y..(y + 2).min(h) {
                for column in x..(x + 2).min(w) {
                    let p = (row * w + column) * 4;
                    b += i32::from(bgra[p]);
                    g += i32::from(bgra[p + 1]);
                    r += i32::from(bgra[p + 2]);
                    count += 1;
                }
            }
            // Average only present pixels at odd right/bottom edges.
            r = (r + count / 2) / count;
            g = (g + count / 2) / count;
            b = (b + count / 2) / count;
            let index = (y / 2) * cw + x / 2;
            output[w * h + index] = (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128) as u8;
            output[w * h + chroma + index] = (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128) as u8;
        }
    }
    Ok(output)
}
fn i420_to_bgra(width: u32, height: u32, i420: &[u8]) -> io::Result<Vec<u8>> {
    let (raw, packed) = geometry(width, height)?;
    if i420.len() != packed {
        return Err(invalid("I420 frame length does not match VP8 geometry"));
    }
    let (w, h) = (width as usize, height as usize);
    let cw = w.div_ceil(2);
    let chroma = cw * h.div_ceil(2);
    let mut output = bytes(raw)?;
    for y in 0..h {
        for x in 0..w {
            let index = (y / 2) * cw + x / 2;
            let c = (i32::from(i420[y * w + x]) - 16).max(0);
            let d = i32::from(i420[w * h + index]) - 128;
            let e = i32::from(i420[w * h + chroma + index]) - 128;
            let pixel = [
                ((298 * c + 516 * d + 128) >> 8).clamp(0, 255) as u8,
                ((298 * c - 100 * d - 208 * e + 128) >> 8).clamp(0, 255) as u8,
                ((298 * c + 409 * e + 128) >> 8).clamp(0, 255) as u8,
                255,
            ];
            output[(y * w + x) * 4..(y * w + x + 1) * 4].copy_from_slice(&pixel);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
