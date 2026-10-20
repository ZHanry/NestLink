//! Live Media Foundation H.264 resources, confined to their creating worker.
//! The initial bridge uses CPU BGRA/NV12 conversion and readback. Its hardware
//! transform flag does not imply a zero-copy capture-to-presentation pipeline.
#![allow(unsafe_code)]
use crate::{EncodedVideo, H264Validator, VideoConfig};
use std::{ffi::c_void, io, marker::PhantomData, ptr::NonNull, rc::Rc};

const PACKET_BYTES: usize = 8 * 1024 * 1024;
unsafe extern "C" {
    fn nl_mf_open(
        encoder: u32,
        hardware: u32,
        width: u32,
        height: u32,
        fps: u32,
        kbps: u32,
        result: *mut *mut c_void,
    ) -> i32;
    fn nl_mf_process(
        handle: *mut c_void,
        input: *const u8,
        length: usize,
        pts: u64,
        keyframe: u32,
        output: *mut u8,
        capacity: usize,
        written: *mut usize,
        output_pts: *mut u64,
    ) -> i32;
    fn nl_mf_bitrate(handle: *mut c_void, kbps: u32) -> i32;
    fn nl_mf_close(handle: *mut c_void);
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
struct Transform {
    handle: NonNull<c_void>,
    raw_bytes: usize,
    last_input: Option<u64>,
    last_output: Option<u64>,
    failed: bool,
    // COM initialization/shutdown and transform calls stay on one worker.
    _thread: PhantomData<Rc<()>>,
}
impl Transform {
    fn new(config: VideoConfig, encoder: bool, hardware: bool) -> io::Result<Self> {
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
                &mut handle,
            )
        };
        if code < 0 {
            return Err(failed("creation", code));
        }
        Ok(Self {
            handle: NonNull::new(handle).ok_or_else(|| failed("creation", code))?,
            raw_bytes,
            last_input: None,
            last_output: None,
            failed: false,
            _thread: PhantomData,
        })
    }
    fn process(
        &mut self,
        input: &[u8],
        pts: u64,
        keyframe: bool,
        output: &mut [u8],
    ) -> io::Result<Option<(usize, u64)>> {
        if self.failed || self.last_input.is_some_and(|previous| pts <= previous) {
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
                output.as_mut_ptr(),
                output.len(),
                &mut written,
                &mut output_pts,
            )
        };
        self.last_input = Some(pts);
        if code < 0 {
            self.failed = true;
            return Err(failed("processing", code));
        }
        if code == 1 {
            return Ok(None);
        }
        if written == 0
            || written > output.len()
            || output_pts > pts
            || self
                .last_output
                .is_some_and(|previous| output_pts <= previous)
        {
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid H.264 output size or timestamp",
            ));
        }
        self.last_output = Some(output_pts);
        Ok(Some((written, output_pts)))
    }
}
impl Drop for Transform {
    fn drop(&mut self) {
        // SAFETY: single thread-confined owner; destruction balances COM/MF
        // initialization only after all transform/device resources are freed.
        unsafe {
            nl_mf_close(self.handle.as_ptr());
        }
    }
}

pub struct MfH264Encoder {
    inner: Transform,
    scratch: Vec<u8>,
    validator: H264Validator,
    parameters: Vec<u8>,
}
impl MfH264Encoder {
    pub fn new(config: VideoConfig, hardware_only: bool) -> io::Result<Self> {
        Ok(Self {
            inner: Transform::new(config, true, hardware_only)?,
            scratch: vec![0; PACKET_BYTES],
            validator: H264Validator::new(config.width, config.height)?,
            parameters: Vec::new(),
        })
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
        if bgra.len() != self.inner.raw_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "H.264 BGRA geometry mismatch",
            ));
        }
        let Some((length, pts_90khz)) =
            self.inner
                .process(bgra, pts, force_keyframe, &mut self.scratch)?
        else {
            return Ok(None);
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
        self.validator.validate(&data)?;
        Ok(Some(EncodedVideo {
            pts_90khz,
            keyframe,
            data,
        }))
    }
    pub fn set_bitrate(&mut self, kbps: u32) -> io::Result<()> {
        if self.inner.failed || !(64..=100_000).contains(&kbps) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid H.264 bitrate/context",
            ));
        }
        // SAFETY: live, exclusively borrowed transform and bounded scalar.
        let code = unsafe { nl_mf_bitrate(self.inner.handle.as_ptr(), kbps) };
        if code < 0 {
            return Err(failed("bitrate update", code));
        }
        Ok(())
    }
}
pub struct MfH264Decoder {
    inner: Transform,
    validator: H264Validator,
}

impl MfH264Decoder {
    pub fn new(width: u32, height: u32, hardware_only: bool) -> io::Result<Self> {
        Ok(Self {
            validator: H264Validator::new(width, height)?,
            inner: Transform::new(
                VideoConfig {
                    width,
                    height,
                    fps: 60,
                    bitrate_kbps: 4_000,
                },
                false,
                hardware_only,
            )?,
        })
    }
    pub fn hardware(&self) -> bool {
        // SAFETY: thread-confined live transform; reads an observed output fact.
        unsafe { nl_mf_hardware_used(self.inner.handle.as_ptr()) != 0 }
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
        self.validator.validate(packet)?;
        let mut output = vec![0; self.inner.raw_bytes];
        let Some((length, pts)) = self.inner.process(packet, pts, false, &mut output)? else {
            return Ok(None);
        };
        if length != output.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "H.264 decoded geometry mismatch",
            ));
        }
        Ok(Some((output, pts)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn software_h264_roundtrip_recovery_idr_and_geometry_rejection() -> io::Result<()> {
        let config = VideoConfig {
            width: 320,
            height: 240,
            fps: 30,
            bitrate_kbps: 2_000,
        };
        let mut encoder = MfH264Encoder::new(config, false)?;
        let pixels = [32, 160, 64, 255].repeat(320 * 240);
        let mut decoder = MfH264Decoder::new(320, 240, false)?;
        let mut outputs = 0;
        let mut idrs = 0;
        for frame in 0..18 {
            let Some(packet) = encoder.encode(&pixels, frame * 3000, frame % 6 == 0)? else {
                continue;
            };
            if packet.keyframe {
                idrs += 1;
                decoder = MfH264Decoder::new(320, 240, false)?;
                assert!(
                    MfH264Decoder::new(640, 480, false)?
                        .decode(&packet.data, packet.pts_90khz)
                        .is_err()
                );
            }
            if let Some((decoded, pts)) = decoder.decode_frame(&packet.data, packet.pts_90khz)? {
                outputs += 1;
                assert!(pts <= packet.pts_90khz);
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
        assert!(encoder.encode(&pixels, 1, false).is_err());
        Ok(())
    }
}
