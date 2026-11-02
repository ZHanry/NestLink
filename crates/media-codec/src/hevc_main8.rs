//! Exact local HEVC Main8 output contract, reusing the bounded Annex-B parser.
//! This is not the v2 wire format, a signed announcement or permission to send.
use crate::{
    VideoConfig,
    hevc_probe::{Sps, Validator},
};
use sha2::{Digest, Sha256};
use std::io;

/// Actual general PTL, coded/crop/display geometry and explicit SDR color.
/// An observed contract requires a complete accepted IDR AU with VPS/SPS/PPS
/// references. A frozen expected target alone is configuration, never evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HevcMain8Contract {
    ptl: [u8; 12],
    coded: [u32; 2],
    crop: [u32; 4],
    display: [u32; 2],
    fps: u32,
    kbps: u32,
}
impl HevcMain8Contract {
    /// Freeze an independently validated signed target. Every actual encoded or
    /// decoded AU still has to match it; this does not attest that a probe ran.
    pub fn from_exact_target(ptl: [u8; 12], config: VideoConfig) -> io::Result<Self> {
        if ptl[0] != 1
            || !matches!(ptl[11], 30 | 60 | 63 | 90 | 93 | 120 | 123 | 150 | 153)
            || config.width == 0
            || config.height == 0
            || config.width > 8192
            || config.height > 8192
            || !config.width.is_multiple_of(8)
            || !config.height.is_multiple_of(8)
            || !(1..=120).contains(&config.fps)
            || !(64..=100_000).contains(&config.bitrate_kbps)
            || u64::from(config.width) * u64::from(config.height) * 4 > 64 * 1024 * 1024
        {
            return Err(io::Error::other("invalid exact expected HEVC Main8 target"));
        }
        Ok(Self {
            ptl,
            coded: [config.width, config.height],
            crop: [0; 4],
            display: [config.width, config.height],
            fps: config.fps,
            kbps: config.bitrate_kbps,
        })
    }
    fn from_sps(info: Sps, config: VideoConfig) -> io::Result<Self> {
        if !info.explicit_bt709_limited
            || info.high_tier
            || info.profile != 1
            || config.width != info.width
            || config.height != info.height
            || !config.width.is_multiple_of(8)
            || !config.height.is_multiple_of(8)
            || info.coded_width != info.width
            || info.coded_height != info.height
            || info.crop != [0; 4]
            || !(1..=120).contains(&config.fps)
            || !(64..=100_000).contains(&config.bitrate_kbps)
            || u64::from(config.width) * u64::from(config.height) * 4 > 64 * 1024 * 1024
            || info.stream_timing.is_some_and(|[units, scale]| {
                u64::from(scale) != u64::from(units) * u64::from(config.fps)
            })
        {
            return Err(io::Error::other(
                "HEVC Main8 requires exact uncropped target, Main tier and explicitly signalled BT709 limited color",
            ));
        }
        let mut ptl = [0; 12];
        ptl[0] = 1; // parser accepted only general_profile_space=0, Main profile.
        ptl[1..5].copy_from_slice(&info.compatibility.to_be_bytes());
        ptl[5..11].copy_from_slice(&info.constraints.to_be_bytes()[2..]);
        ptl[11] = info.level as u8;
        Self::from_exact_target(ptl, config)
    }
    pub fn observe(access_unit: &[u8], config: VideoConfig) -> io::Result<Self> {
        let mut validator = Validator::exact_main8();
        validator.validate(access_unit, config.width, config.height)?;
        Self::from_sps(
            validator
                .info()
                .ok_or_else(|| io::Error::other("missing actual HEVC SPS"))?,
            config,
        )
    }
    pub fn config(self) -> VideoConfig {
        VideoConfig {
            width: self.display[0],
            height: self.display[1],
            fps: self.fps,
            bitrate_kbps: self.kbps,
        }
    }
    pub fn general_profile_tier_level(self) -> [u8; 12] {
        self.ptl
    }
    pub fn digest(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"nestlink/local-hevc-main8-output/v1\0");
        hash.update(self.ptl);
        for value in self
            .coded
            .into_iter()
            .chain(self.crop)
            .chain(self.display)
            .chain([self.fps, self.kbps])
        {
            hash.update(value.to_be_bytes());
        }
        hash.update([1, 1, 1, 0, 1, 8]); // actual BT709 primaries/transfer/matrix, limited, 420, 8-bit.
        hash.finalize().into()
    }
}

/// Transactional parameter-set history pinned to an exact observed target.
/// A rejected changed AU never replaces previously accepted parser state.
#[derive(Clone)]
pub struct HevcMain8Admission {
    expected: HevcMain8Contract,
    validator: Validator,
}
impl HevcMain8Admission {
    pub fn new(expected: HevcMain8Contract) -> Self {
        Self {
            expected,
            validator: Validator::exact_main8(),
        }
    }
    pub fn validate(&mut self, bytes: &[u8]) -> io::Result<()> {
        let config = self.expected.config();
        let mut next = self.validator.clone();
        next.validate(bytes, config.width, config.height)?;
        let actual = HevcMain8Contract::from_sps(
            next.info()
                .ok_or_else(|| io::Error::other("missing actual HEVC SPS"))?,
            config,
        )?;
        if actual != self.expected {
            return Err(io::Error::other(
                "actual HEVC PTL/geometry/color differs from this exact owner contract",
            ));
        }
        self.validator = next;
        Ok(())
    }
}
