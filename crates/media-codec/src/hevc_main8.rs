//! Exact local HEVC Main8/Main10 SDR contract, reusing the bounded Annex-B parser.
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
pub struct HevcContract {
    ptl: [u8; 12],
    coded: [u32; 2],
    crop: [u32; 4],
    display: [u32; 2],
    fps: u32,
    kbps: u32,
    bit_depth: u8,
}
/// Compatibility type name; the original observe/from_exact_target methods
/// remain strictly Main8. Main10 always needs its explicit constructor.
pub type HevcMain8Contract = HevcContract;
impl HevcContract {
    /// Bounded exact workload, not a claim that an adapter supports this target.
    /// The same allocation ceiling applies to probes and original live owners.
    pub fn validate_config(config: VideoConfig) -> io::Result<()> {
        if !(16..=8192).contains(&config.width)
            || !(16..=8192).contains(&config.height)
            || !config.width.is_multiple_of(8)
            || !config.height.is_multiple_of(8)
            || !(1..=144).contains(&config.fps)
            || !(64..=100_000).contains(&config.bitrate_kbps)
            || u64::from(config.width) * u64::from(config.height) * 4 > 64 * 1024 * 1024
        {
            return Err(io::Error::other(
                "unsupported exact HEVC allocation/rate budget",
            ));
        }
        Ok(())
    }
    /// Match the independent v4 format budget before opening any P010 owner.
    /// Main8 retains its original four-byte surface allowance.
    pub fn validate_main10_config(config: VideoConfig) -> io::Result<()> {
        Self::validate_config(config)?;
        if u64::from(config.width) * u64::from(config.height) * 8 > 64 * 1024 * 1024 {
            return Err(io::Error::other(
                "unsupported exact Main10 allocation budget",
            ));
        }
        Ok(())
    }
    /// Freeze an independently validated signed target. Every actual encoded or
    /// decoded AU still has to match it; this does not attest that a probe ran.
    pub fn from_exact_target(ptl: [u8; 12], config: VideoConfig) -> io::Result<Self> {
        Self::from_profile_target(ptl, config, 8)
    }
    pub fn from_main10_target(ptl: [u8; 12], config: VideoConfig) -> io::Result<Self> {
        Self::from_profile_target(ptl, config, 10)
    }
    fn from_profile_target(ptl: [u8; 12], config: VideoConfig, bit_depth: u8) -> io::Result<Self> {
        if bit_depth == 10 {
            Self::validate_main10_config(config)?;
        } else {
            Self::validate_config(config)?;
        }
        let profile = if bit_depth == 10 { 2 } else { 1 };
        if ptl[0] != profile
            || !matches!(
                ptl[11],
                30 | 60 | 63 | 90 | 93 | 120 | 123 | 150 | 153 | 156 | 180 | 183 | 186
            )
        {
            return Err(io::Error::other(
                "invalid exact expected HEVC profile/depth target",
            ));
        }
        Ok(Self {
            ptl,
            coded: [config.width, config.height],
            crop: [0; 4],
            display: [config.width, config.height],
            fps: config.fps,
            kbps: config.bitrate_kbps,
            bit_depth,
        })
    }
    fn from_sps(info: Sps, config: VideoConfig) -> io::Result<Self> {
        let profile = if info.bit_depth == 10 { 2 } else { 1 };
        if !info.explicit_bt709_limited
            || info.high_tier
            || info.profile != profile
            || config.width != info.width
            || config.height != info.height
            || !config.width.is_multiple_of(8)
            || !config.height.is_multiple_of(8)
            || info.coded_width != info.width
            || info.coded_height != info.height
            || info.crop != [0; 4]
            || !(1..=144).contains(&config.fps)
            || !(64..=100_000).contains(&config.bitrate_kbps)
            || u64::from(config.width) * u64::from(config.height) * 4 > 64 * 1024 * 1024
            || info.stream_timing.is_some_and(|[units, scale]| {
                u64::from(scale) != u64::from(units) * u64::from(config.fps)
            })
        {
            return Err(io::Error::other(
                "HEVC requires exact uncropped profile/depth target, Main tier and explicitly signalled BT709 limited color",
            ));
        }
        let mut ptl = [0; 12];
        ptl[0] = info.profile as u8; // Exact parser accepts only the selected profile/depth.
        ptl[1..5].copy_from_slice(&info.compatibility.to_be_bytes());
        ptl[5..11].copy_from_slice(&info.constraints.to_be_bytes()[2..]);
        ptl[11] = info.level as u8;
        Self::from_profile_target(ptl, config, info.bit_depth)
    }
    pub fn observe(access_unit: &[u8], config: VideoConfig) -> io::Result<Self> {
        Self::observe_depth(access_unit, config, 8)
    }
    pub fn observe_main10(access_unit: &[u8], config: VideoConfig) -> io::Result<Self> {
        Self::observe_depth(access_unit, config, 10)
    }
    fn observe_depth(access_unit: &[u8], config: VideoConfig, bit_depth: u8) -> io::Result<Self> {
        let mut validator = if bit_depth == 10 {
            Validator::exact_main10()
        } else {
            Validator::exact_main8()
        };
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
    pub fn bit_depth(self) -> u8 {
        self.bit_depth
    }
    pub fn digest(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(if self.bit_depth == 10 {
            b"nestlink/local-hevc-main10-output/v1\0".as_slice()
        } else {
            b"nestlink/local-hevc-main8-output/v1\0".as_slice()
        });
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
        hash.update([1, 1, 1, 0, 1, self.bit_depth]); // actual BT709 limited 420, exact depth.
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
    #[cfg(windows)]
    pub(crate) fn config(&self) -> VideoConfig {
        self.expected.config()
    }
    pub fn new(expected: HevcMain8Contract) -> Self {
        Self {
            expected,
            validator: if expected.bit_depth() == 10 {
                Validator::exact_main10()
            } else {
                Validator::exact_main8()
            },
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
