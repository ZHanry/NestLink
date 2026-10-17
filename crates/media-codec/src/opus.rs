//! Fixed 48 kHz / 20 ms Opus packets with explicit negotiated channel identity.
//! Run each codec on the caller's dedicated media thread, in packet order.
//! These synchronous local codecs confer no capture, playback or session rights.
#![allow(unsafe_code)]

use std::{ffi::c_void, io, ptr::NonNull};

pub const OPUS_SAMPLE_RATE: u32 = 48_000;
/// PCM frames per channel. Stereo uses 1,920 interleaved i16 samples.
pub const OPUS_SAMPLES_PER_CHANNEL: usize = OPUS_SAMPLE_RATE as usize / 50;
pub const OPUS_MAX_PACKET_BYTES: usize = 1275;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpusConfig {
    pub channels: u8,
    /// Target bits per second, inclusive range 6,000..=256,000.
    pub bitrate: u32,
}
impl OpusConfig {
    fn validate(self) -> io::Result<()> {
        channels(self.channels)?;
        if !(6_000..=256_000).contains(&self.bitrate) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Opus bitrate must be 6000..=256000 bps",
            ));
        }
        Ok(())
    }
}
fn channels(channels: u8) -> io::Result<()> {
    if !(1..=2).contains(&channels) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Opus requires one or two channels",
        ));
    }
    Ok(())
}
fn error(operation: &str, code: i32) -> io::Error {
    let kind = match code {
        -1 => io::ErrorKind::InvalidInput,
        -4 => io::ErrorKind::InvalidData,
        -5 => io::ErrorKind::Unsupported,
        -7 => io::ErrorKind::OutOfMemory,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, format!("Opus {operation} failed ({code})"))
}
unsafe extern "C" {
    fn nl_opus_encoder_new(channels: u32, bitrate: u32, out: *mut *mut c_void) -> i32;
    fn nl_opus_encoder_free(encoder: *mut c_void);
    fn nl_opus_encode(
        encoder: *mut c_void,
        pcm: *const i16,
        samples: u32,
        packet: *mut u8,
        capacity: u32,
    ) -> i32;
    fn nl_opus_encoder_reset(encoder: *mut c_void) -> i32;
    fn nl_opus_decoder_new(channels: u32, out: *mut *mut c_void) -> i32;
    fn nl_opus_decoder_free(decoder: *mut c_void);
    fn nl_opus_validate_packet(packet: *const u8, bytes: u32, channels: u32) -> i32;
    fn nl_opus_decode(
        decoder: *mut c_void,
        packet: *const u8,
        bytes: u32,
        pcm: *mut i16,
        samples: u32,
    ) -> i32;
    fn nl_opus_conceal(decoder: *mut c_void, pcm: *mut i16, samples: u32) -> i32;
    fn nl_opus_decoder_reset(decoder: *mut c_void) -> i32;
}

/// One ordered stream. Exclusive ownership permits moving it to a media worker;
/// the opaque handle is not Sync and calls require a mutable borrow.
pub struct OpusEncoder {
    handle: NonNull<c_void>,
    config: OpusConfig,
}
// SAFETY: Opus permits sequential access from different threads. This owner is
// never cloned/shared, and no borrowed input/output survives a synchronous call.
// The upstream library must be built without NONTHREADSAFE_PSEUDOSTACK.
unsafe impl Send for OpusEncoder {}

impl OpusEncoder {
    pub fn new(config: OpusConfig) -> io::Result<Self> {
        config.validate()?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: out points to initialized pointer storage; the wrapper owns
        // allocation/initialization and frees partial state before failure.
        let code =
            unsafe { nl_opus_encoder_new(u32::from(config.channels), config.bitrate, &mut handle) };
        if code != 0 {
            return Err(error("encoder creation", code));
        }
        let handle = NonNull::new(handle)
            .ok_or_else(|| io::Error::other("Opus encoder returned no state"))?;
        Ok(Self { handle, config })
    }
    pub fn config(&self) -> OpusConfig {
        self.config
    }
    /// Encode exactly 20 ms of signed native-endian PCM; stereo is interleaved.
    /// DTX and in-band FEC are disabled. Each result contains a real Opus packet.
    pub fn encode(&mut self, pcm: &[i16]) -> io::Result<Vec<u8>> {
        if pcm.len() != OPUS_SAMPLES_PER_CHANNEL * usize::from(self.config.channels) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Opus requires exactly 960 PCM frames per channel",
            ));
        }
        let mut packet = vec![0; OPUS_MAX_PACKET_BYTES];
        // SAFETY: exclusively owned live state; slice lengths match both C ABI
        // counts, with a fixed writable capacity. C retains no slice pointer.
        let bytes = unsafe {
            nl_opus_encode(
                self.handle.as_ptr(),
                pcm.as_ptr(),
                pcm.len() as u32,
                packet.as_mut_ptr(),
                packet.len() as u32,
            )
        };
        if bytes <= 0 {
            return Err(error("encoding", bytes));
        }
        let bytes = usize::try_from(bytes).map_err(io::Error::other)?;
        if bytes > packet.len() {
            return Err(io::Error::other("Opus exceeded its output bound"));
        }
        packet.truncate(bytes);
        Ok(packet)
    }
    /// Forget stream history without changing the negotiated format or bitrate.
    pub fn reset(&mut self) -> io::Result<()> {
        // SAFETY: exclusively borrowed, initialized encoder.
        let code = unsafe { nl_opus_encoder_reset(self.handle.as_ptr()) };
        if code != 0 {
            return Err(error("encoder reset", code));
        }
        Ok(())
    }
}
impl Drop for OpusEncoder {
    fn drop(&mut self) {
        // SAFETY: the unique owner destroys its initialized C state exactly once.
        unsafe { nl_opus_encoder_free(self.handle.as_ptr()) };
    }
}

/// One ordered decoder stream, with the same ownership rules as OpusEncoder.
pub struct OpusDecoder {
    handle: NonNull<c_void>,
    channels: u8,
}
// SAFETY: identical exclusive-state/threading argument to OpusEncoder.
unsafe impl Send for OpusDecoder {}
impl OpusDecoder {
    pub fn new(channel_count: u8) -> io::Result<Self> {
        channels(channel_count)?;
        let mut handle = std::ptr::null_mut();
        // SAFETY: out is initialized pointer storage, with C cleaning up failures.
        let code = unsafe { nl_opus_decoder_new(u32::from(channel_count), &mut handle) };
        if code != 0 {
            return Err(error("decoder creation", code));
        }
        let handle = NonNull::new(handle)
            .ok_or_else(|| io::Error::other("Opus decoder returned no state"))?;
        Ok(Self {
            handle,
            channels: channel_count,
        })
    }
    pub fn channels(&self) -> u8 {
        self.channels
    }
    /// Parse the complete packet's framing, channel identity and 20 ms duration
    /// without changing decoder history. Compressed syntax is still decoded
    /// separately; this check lets the session reject malformed loss triggers.
    pub fn validate_packet(&self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() || packet.len() > OPUS_MAX_PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Opus packet must contain 1..=1275 bytes",
            ));
        }
        // SAFETY: bounded borrowed packet and fixed negotiated channel count;
        // the C parser does not retain data or modify a decoder context.
        let code = unsafe {
            nl_opus_validate_packet(
                packet.as_ptr(),
                packet.len() as u32,
                u32::from(self.channels),
            )
        };
        if code != 0 {
            return Err(error("packet validation", code));
        }
        Ok(())
    }
    /// Decode exactly one nonempty 20 ms packet with the negotiated channels.
    /// Packet framing, duration and channel identity are checked before decode;
    /// no sample buffer is sized from untrusted packet metadata.
    pub fn decode(&mut self, packet: &[u8]) -> io::Result<Vec<i16>> {
        if packet.is_empty() || packet.len() > OPUS_MAX_PACKET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Opus packet must contain 1..=1275 bytes",
            ));
        }
        let mut pcm = vec![0; OPUS_SAMPLES_PER_CHANNEL * usize::from(self.channels)];
        // SAFETY: fixed, exact PCM capacity; packet count comes from its bounded
        // slice. C validates framing before touching decoder state.
        let samples = unsafe {
            nl_opus_decode(
                self.handle.as_ptr(),
                packet.as_ptr(),
                packet.len() as u32,
                pcm.as_mut_ptr(),
                pcm.len() as u32,
            )
        };
        Self::decoded(samples, pcm)
    }
    /// Synthesize exactly one missing 20 ms interval from decoder history.
    /// This is PLC, not recovery of an FEC packet and not authenticated audio.
    pub fn conceal_loss(&mut self) -> io::Result<Vec<i16>> {
        let mut pcm = vec![0; OPUS_SAMPLES_PER_CHANNEL * usize::from(self.channels)];
        // SAFETY: exclusively owned state and the fixed, exact writable buffer.
        let samples =
            unsafe { nl_opus_conceal(self.handle.as_ptr(), pcm.as_mut_ptr(), pcm.len() as u32) };
        Self::decoded(samples, pcm)
    }
    fn decoded(samples: i32, pcm: Vec<i16>) -> io::Result<Vec<i16>> {
        if samples < 0 {
            return Err(error("decoding", samples));
        }
        if samples != OPUS_SAMPLES_PER_CHANNEL as i32 {
            return Err(io::Error::other(
                "Opus changed the negotiated packet duration",
            ));
        }
        Ok(pcm)
    }
    pub fn reset(&mut self) -> io::Result<()> {
        // SAFETY: exclusively borrowed, initialized decoder.
        let code = unsafe { nl_opus_decoder_reset(self.handle.as_ptr()) };
        if code != 0 {
            return Err(error("decoder reset", code));
        }
        Ok(())
    }
}
impl Drop for OpusDecoder {
    fn drop(&mut self) {
        // SAFETY: this unique owner destroys the C state exactly once.
        unsafe { nl_opus_decoder_free(self.handle.as_ptr()) };
    }
}

#[cfg(test)]
mod tests;
