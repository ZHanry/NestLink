use nestlink_remote::audio::{AudioChunk, CHUNK_FRAMES, CapturedAudio};
use std::{
    io,
    time::{Duration, Instant},
};

/// Assemble device-positioned packets without filling unknown gaps with old PCM.
pub(crate) struct Assembler {
    source: u32,
    channels: u8,
    origin: Option<u64>,
    expected: Option<u64>,
    next: u64,
    partial: Vec<i16>,
    captured_at: Option<Instant>,
}
impl Assembler {
    pub(crate) fn new(source: u32, channels: u8) -> io::Result<Self> {
        if !(1..=2).contains(&channels) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported PCM channels",
            ));
        }
        Ok(Self {
            source,
            channels,
            origin: None,
            expected: None,
            next: 0,
            partial: Vec::with_capacity(CHUNK_FRAMES * usize::from(channels)),
            captured_at: None,
        })
    }
    pub(crate) fn push(
        &mut self,
        position: u64,
        captured_at: Instant,
        discontinuity: bool,
        samples: &[i16],
    ) -> io::Result<Vec<CapturedAudio>> {
        let channels = usize::from(self.channels);
        let frames = samples.len() / channels;
        if !samples.len().is_multiple_of(channels)
            || frames == 0
            || frames > CHUNK_FRAMES * 2
            || captured_at > Instant::now()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid system PCM packet",
            ));
        }
        if self.expected.is_some_and(|expected| position < expected) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "system audio device clock regressed",
            ));
        }
        let origin = *self.origin.get_or_insert(position);
        let relative = position
            .checked_sub(origin)
            .ok_or_else(|| io::Error::other("PCM origin regressed"))?;
        let end = relative
            .checked_add(frames as u64)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "PCM clock overflow"))?;
        if self.expected != Some(position) || discontinuity {
            self.partial.clear();
            self.captured_at = None;
            self.next = relative.div_ceil(CHUNK_FRAMES as u64) * CHUNK_FRAMES as u64;
        }
        self.expected = position.checked_add(frames as u64);
        if self.expected.is_none() {
            return Err(io::Error::other("device PCM clock overflow"));
        }
        let mut cursor = relative;
        let mut output = Vec::with_capacity(2);
        while cursor < end {
            if cursor < self.next {
                cursor = end.min(self.next);
                continue;
            }
            let remaining = CHUNK_FRAMES - self.partial.len() / channels;
            let take = remaining.min((end - cursor) as usize);
            let offset = (cursor - relative) as usize;
            if self.partial.is_empty() {
                self.captured_at = captured_at.checked_add(Duration::from_nanos(
                    (offset as u64) * 1_000_000_000 / 48_000,
                ));
            }
            self.partial
                .extend_from_slice(&samples[offset * channels..(offset + take) * channels]);
            cursor += take as u64;
            if self.partial.len() == CHUNK_FRAMES * channels {
                output.push(CapturedAudio {
                    captured_at: self
                        .captured_at
                        .take()
                        .ok_or_else(|| io::Error::other("PCM timestamp missing"))?,
                    chunk: AudioChunk {
                        source: self.source,
                        channels: self.channels,
                        pts_48khz: self.next,
                        samples: std::mem::take(&mut self.partial),
                    },
                });
                self.next += CHUNK_FRAMES as u64;
            }
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_packets_preserve_stereo_order_and_sample_clock() -> io::Result<()> {
        let mut pcm = Assembler::new(9, 2)?;
        let start = Instant::now() - Duration::from_millis(80);
        let first: Vec<_> = (0..800).map(|v| v as i16).collect();
        assert!(pcm.push(12_345, start, true, &first)?.is_empty());
        let second: Vec<_> = (800..2720).map(|v| v as i16).collect();
        let mut output = pcm.push(12_745, start + Duration::from_millis(8), false, &second)?;
        assert_eq!(output.len(), 1);
        let packet = output.remove(0);
        assert_eq!(packet.captured_at, start);
        assert_eq!(packet.chunk.pts_48khz, 0);
        assert_eq!(packet.chunk.source, 9);
        assert!(
            packet
                .chunk
                .samples
                .iter()
                .copied()
                .eq((0..1920).map(|v| v as i16))
        );
        let output = pcm.push(
            13_705,
            start + Duration::from_millis(28),
            false,
            &vec![7; 1120],
        )?;
        assert_eq!(output[0].chunk.pts_48khz, 960);
        Ok(())
    }
    #[test]
    fn gaps_discard_partial_audio_and_never_replay_or_iterate_over_gap() -> io::Result<()> {
        let mut pcm = Assembler::new(0, 1)?;
        let now = Instant::now() - Duration::from_secs(1);
        assert!(pcm.push(0, now, false, &[3; 500])?.is_empty());
        assert!(pcm.push(700, now, true, &[4; 500])?.is_empty());
        let output = pcm.push(1200, now, false, &[5; 720])?;
        assert_eq!(output[0].chunk.pts_48khz, 960);
        assert!(output[0].chunk.samples[..240].iter().all(|v| *v == 4));
        assert!(output[0].chunk.samples[240..].iter().all(|v| *v == 5));
        let jump = 960 * 1_000_000;
        let output = pcm.push(jump, now, false, &[6; 960])?;
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].chunk.pts_48khz, jump);
        assert!(pcm.push(jump, now, false, &[6; 960]).is_err());
        assert!(pcm.push(u64::MAX, now, false, &[6; 960]).is_err());
        Ok(())
    }
}
