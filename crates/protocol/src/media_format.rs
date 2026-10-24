//! Discrete format data validation; never authority or evidence of a backend probe.
//! No wire/permit negotiation is added by this internal legacy-admission slice.
use crate::{ContractError, ErrorCode, RAW_FRAME_BYTES, VIDEO_DIMENSION};
use sha2::{Digest, Sha256};

const VERSION: u16 = 2;
const MAX_FORMATS: usize = 64;
const MAX_FPS: u32 = 144;
const FORMAT_DOMAIN: &[u8] = b"nestlink/media-format/v2\0";
const SET_DOMAIN: &[u8] = b"nestlink/media-format-set/v2\0";
type Result<T> = std::result::Result<T, ContractError>;
fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}

macro_rules! field {
    ($name:ident { $($variant:ident = $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
        #[repr(u8)]
        pub enum $name { $($variant = $value),+ }
        impl TryFrom<u32> for $name {
            type Error = ContractError;
            fn try_from(value: u32) -> Result<Self> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(invalid("unknown media format enum value")),
                }
            }
        }
    };
}
field!(Codec { Vp8 = 1, H264 = 2, Hevc = 3 });
field!(Profile { Vp8 = 1, H264Baseline = 2, HevcMain = 3, HevcMain10 = 4, HevcRange444 = 5 });
field!(Tier { NotApplicable = 0, Main = 1, High = 2 });
field!(Chroma { Yuv420 = 1, Yuv444 = 2 });
field!(BitDepth { Eight = 8, Ten = 10 });
field!(Primaries { Unspecified = 0, Bt709 = 1, Bt2020 = 2 });
field!(Transfer { Unspecified = 0, Bt709 = 1, Srgb = 2, Pq = 3, Hlg = 4 });
field!(Matrix { Bt709 = 1, Bt2020NonConstant = 2, Bt601 = 3 });
field!(Range { Limited = 1, Full = 2 });

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Color {
    pub primaries: Primaries,
    pub transfer: Transfer,
    pub matrix: Matrix,
    pub range: Range,
}
impl Color {
    /// Existing VP8 Rust conversion is BT601 studio range; capture does not
    /// establish complete primaries/transfer metadata. Do not invent BT709.
    pub const LEGACY_VP8_BT601: Self = Self {
        primaries: Primaries::Unspecified,
        transfer: Transfer::Unspecified,
        matrix: Matrix::Bt601,
        range: Range::Limited,
    };
    pub const SDR_BT709_LIMITED: Self = Self {
        primaries: Primaries::Bt709,
        transfer: Transfer::Bt709,
        matrix: Matrix::Bt709,
        range: Range::Limited,
    };
    fn validate(self, depth: BitDepth) -> Result<()> {
        // Matrix and primaries are independent fields; never infer one from the
        // other. Undefined legacy metadata is permitted only by the VP8 branch.
        if matches!(self.transfer, Transfer::Pq | Transfer::Hlg)
            && (depth != BitDepth::Ten || self.primaries != Primaries::Bt2020)
        {
            return Err(invalid(
                "HDR transfer requires independent ten-bit BT2020 support",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FrameRate {
    pub numerator: u32,
    pub denominator: u32,
}
fn gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}
impl FrameRate {
    pub fn new(numerator: u32, denominator: u32) -> Result<Self> {
        if numerator == 0 || denominator == 0 {
            return Err(invalid("zero video frame rate"));
        }
        let divisor = gcd(numerator, denominator);
        let value = Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(self) -> Result<()> {
        if self.numerator == 0
            || self.denominator == 0
            || self.denominator > 100_000
            || gcd(self.numerator, self.denominator) != 1
            || u64::from(self.numerator) > u64::from(MAX_FPS) * u64::from(self.denominator)
        {
            return Err(invalid("invalid or noncanonical video frame rate"));
        }
        Ok(())
    }
}

/// Coded luma samples and crop offsets in luma samples (never SPS crop units).
/// Display width/height remain explicit in VideoFormat and must equal the crop.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Geometry {
    pub coded_width: u32,
    pub coded_height: u32,
    /// Left, right, top, bottom, in luma samples.
    pub crop: [u32; 4],
}
impl Geometry {
    pub const fn uncropped(width: u32, height: u32) -> Self {
        Self {
            coded_width: width,
            coded_height: height,
            crop: [0; 4],
        }
    }
    fn validate(self, format: VideoFormat) -> Result<()> {
        let [left, right, top, bottom] = self.crop;
        let cropped_width = left
            .checked_add(right)
            .and_then(|v| self.coded_width.checked_sub(v));
        let cropped_height = top
            .checked_add(bottom)
            .and_then(|v| self.coded_height.checked_sub(v));
        let bytes_per_pixel = if format.bit_depth == BitDepth::Ten {
            8
        } else {
            4
        };
        // Existing H264 validator permits bounded macroblock padding above the
        // 64MiB display budget. Keep that independent coded-surface limit.
        let budget = if format.codec == Codec::H264 {
            65 * 1024 * 1024
        } else {
            RAW_FRAME_BYTES
        };
        if cropped_width != Some(format.width)
            || cropped_height != Some(format.height)
            || self.coded_width == 0
            || self.coded_height == 0
            || u64::from(self.coded_width) > VIDEO_DIMENSION
            || u64::from(self.coded_height) > VIDEO_DIMENSION
            || u64::from(self.coded_width) * u64::from(self.coded_height) * bytes_per_pixel > budget
        {
            return Err(invalid("invalid coded/display/crop geometry"));
        }
        match format.codec {
            Codec::Vp8 if self != Self::uncropped(format.width, format.height) => {
                return Err(invalid("VP8 does not expose SPS cropping"));
            }
            Codec::H264
                if !self.coded_width.is_multiple_of(16)
                    || !self.coded_height.is_multiple_of(16)
                    || self.crop.iter().any(|v| !v.is_multiple_of(2)) =>
            {
                return Err(invalid("unsupported progressive H264 crop units"));
            }
            // HEVC remains syntax-only. No production PTL/parser contract is
            // claimed; retain the existing restricted uncropped catalog.
            Codec::Hevc if self != Self::uncropped(format.width, format.height) => {
                return Err(invalid("HEVC crop requires a future SPS contract"));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct VideoFormat {
    pub codec: Codec,
    pub profile: Profile,
    /// H264 level_idc, HEVC general_level_idc; zero only for VP8.
    pub level: u8,
    /// Exact SPS constraint_set0..5 flags and reserved_zero_2bits byte.
    /// Zero for non-H264 syntax; not an HEVC PTL representation.
    pub h264_constraints: u8,
    pub geometry: Geometry,
    pub tier: Tier,
    pub chroma: Chroma,
    pub bit_depth: BitDepth,
    pub color: Color,
    pub width: u32,
    pub height: u32,
    pub frame_rate: FrameRate,
    /// Configured bitrate ceiling for this discrete format. Executable
    /// capability admission requires separate probe evidence; this value cannot
    /// synthesize a different resolution/fps/chroma combination.
    pub max_kbps: u32,
}
impl VideoFormat {
    pub fn validate(self) -> Result<()> {
        self.geometry.validate(self)?;
        self.frame_rate.validate()?;
        self.color.validate(self.bit_depth)?;
        let width = u64::from(self.width);
        let height = u64::from(self.height);
        // Conservative output budget includes a possible 16-bit RGBA surface.
        let bytes_per_pixel = if self.bit_depth == BitDepth::Ten {
            8
        } else {
            4
        };
        if width == 0
            || height == 0
            || width > VIDEO_DIMENSION
            || height > VIDEO_DIMENSION
            || width
                .checked_mul(height)
                .and_then(|v| v.checked_mul(bytes_per_pixel))
                .is_none_or(|v| v > RAW_FRAME_BYTES)
            || self.max_kbps == 0
            || self.max_kbps > 1_000_000
            || self.codec != Codec::Vp8
                && self.chroma == Chroma::Yuv420
                && (!self.width.is_multiple_of(2) || !self.height.is_multiple_of(2))
        {
            return Err(invalid(
                "video geometry or bitrate exceeds bounded format budget",
            ));
        }
        let legacy_pixels = self.chroma == Chroma::Yuv420 && self.bit_depth == BitDepth::Eight;
        match (self.codec, self.profile) {
            (Codec::Vp8, Profile::Vp8) => {
                if !legacy_pixels
                    || self.h264_constraints != 0
                    || self.level != 0
                    || self.tier != Tier::NotApplicable
                    || self.color != Color::LEGACY_VP8_BT601
                {
                    return Err(invalid("unsupported VP8 format combination"));
                }
            }
            (Codec::H264, Profile::H264Baseline) => {
                if !legacy_pixels
                    || self.h264_constraints & 3 != 0
                    || (self.level == 11 && self.h264_constraints & 0x10 != 0)
                    || self.tier != Tier::NotApplicable
                    || self.color != Color::SDR_BT709_LIMITED
                {
                    return Err(invalid("unsupported H264 Baseline format combination"));
                }
                let (max_fs, max_mbps, max_kbps) =
                    h264_limits(self.level).ok_or_else(|| invalid("unsupported H264 level"))?;
                let columns = u64::from(self.geometry.coded_width / 16);
                let rows = u64::from(self.geometry.coded_height / 16);
                if columns * rows > max_fs
                    || columns * columns > max_fs * 8
                    || rows * rows > max_fs * 8
                    || u64::from(self.max_kbps) > max_kbps
                    || columns * rows * u64::from(self.frame_rate.numerator)
                        > max_mbps * u64::from(self.frame_rate.denominator)
                {
                    return Err(invalid("H264 format exceeds level limits"));
                }
            }
            (Codec::Hevc, Profile::HevcMain | Profile::HevcMain10 | Profile::HevcRange444) => {
                // Restricted first-slice catalog: dimensions designate both
                // coded luma and uncropped display, aligned to the minimum 8x8
                // luma block. Display area alone undercounts padded geometry.
                // Actual SPS validation must require exact coded dimensions
                // and zero crop. Extending this catalog needs an actual HEVC
                // SPS/PTL parser and backend evidence, not implicit rounding.
                if self.h264_constraints != 0
                    || !self.width.is_multiple_of(8)
                    || !self.height.is_multiple_of(8)
                {
                    return Err(invalid("HEVC requires uncropped 8-aligned coded geometry"));
                }
                let pixels_valid = match self.profile {
                    Profile::HevcMain => legacy_pixels,
                    Profile::HevcMain10 => self.chroma == Chroma::Yuv420,
                    Profile::HevcRange444 => self.chroma == Chroma::Yuv444,
                    _ => false,
                };
                if self.color.primaries == Primaries::Unspecified
                    || self.color.transfer == Transfer::Unspecified
                {
                    return Err(invalid("HEVC requires explicit color metadata"));
                }
                let (max_picture, max_samples, main_kbps, high_kbps) =
                    hevc_limits(self.level).ok_or_else(|| invalid("unsupported HEVC level"))?;
                let max_kbps = match self.tier {
                    Tier::Main => main_kbps,
                    Tier::High if high_kbps > 0 => high_kbps,
                    _ => return Err(invalid("HEVC tier unavailable for this level")),
                };
                if !pixels_valid
                    || width * height > max_picture
                    || width * width > max_picture * 8
                    || height * height > max_picture * 8
                    || width * height * u64::from(self.frame_rate.numerator)
                        > max_samples * u64::from(self.frame_rate.denominator)
                    || u64::from(self.max_kbps) > max_kbps
                {
                    return Err(invalid("HEVC profile or level format mismatch"));
                }
                // Conservative Main-profile bitrate ceiling also applies to the
                // draft range-extension catalog. Full RExt constraints still
                // require actual SPS parsing/backend probe before announcement.
            }
            _ => return Err(invalid("codec and profile differ")),
        }
        Ok(())
    }

    pub fn legacy_vp8(width: u32, height: u32, fps: FrameRate, kbps: u32) -> Result<Self> {
        Self::legacy(Codec::Vp8, Profile::Vp8, 0, width, height, fps, kbps)
    }
    /// Target description only. Actual sender receipts use h264_observed.
    pub fn legacy_h264(
        level: u8,
        width: u32,
        height: u32,
        fps: FrameRate,
        kbps: u32,
    ) -> Result<Self> {
        Self::legacy(
            Codec::H264,
            Profile::H264Baseline,
            level,
            width,
            height,
            fps,
            kbps,
        )
    }
    pub fn h264_observed(
        level: u8,
        constraints: u8,
        geometry: Geometry,
        width: u32,
        height: u32,
        fps: FrameRate,
        kbps: u32,
    ) -> Result<Self> {
        let mut format = Self::legacy_h264(level, width, height, fps, kbps)?;
        format.h264_constraints = constraints;
        format.geometry = geometry;
        format.validate()?;
        Ok(format)
    }
    fn legacy(
        codec: Codec,
        profile: Profile,
        level: u8,
        width: u32,
        height: u32,
        frame_rate: FrameRate,
        max_kbps: u32,
    ) -> Result<Self> {
        let format = Self {
            codec,
            profile,
            level,
            h264_constraints: 0,
            geometry: if codec == Codec::H264 {
                let coded_width = width
                    .checked_add(15)
                    .ok_or_else(|| invalid("geometry overflow"))?
                    / 16
                    * 16;
                let coded_height = height
                    .checked_add(15)
                    .ok_or_else(|| invalid("geometry overflow"))?
                    / 16
                    * 16;
                Geometry {
                    coded_width,
                    coded_height,
                    crop: [0, coded_width - width, 0, coded_height - height],
                }
            } else {
                Geometry::uncropped(width, height)
            },
            tier: Tier::NotApplicable,
            chroma: Chroma::Yuv420,
            bit_depth: BitDepth::Eight,
            color: if codec == Codec::Vp8 {
                Color::LEGACY_VP8_BT601
            } else {
                Color::SDR_BT709_LIMITED
            },
            width,
            height,
            frame_rate,
            max_kbps,
        };
        format.validate()?;
        Ok(format)
    }

    fn canonical(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(57);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[
            self.codec as u8,
            self.profile as u8,
            self.level,
            self.h264_constraints,
            self.tier as u8,
            self.chroma as u8,
            self.bit_depth as u8,
            self.color.primaries as u8,
            self.color.transfer as u8,
            self.color.matrix as u8,
            self.color.range as u8,
        ]);
        for value in [
            self.width,
            self.height,
            self.geometry.coded_width,
            self.geometry.coded_height,
            self.geometry.crop[0],
            self.geometry.crop[1],
            self.geometry.crop[2],
            self.geometry.crop[3],
            self.frame_rate.numerator,
            self.frame_rate.denominator,
            self.max_kbps,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes
    }
    pub fn digest(self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(FORMAT_DOMAIN);
        hash.update(self.canonical());
        Ok(hash.finalize().into())
    }
}

/// Exact probed configurations. Private storage prevents post-validation mutation.
/// This type is data validation, never proof that a hardware probe happened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormatSet(Vec<VideoFormat>);
impl FormatSet {
    pub fn from_versioned(version: u16, formats: Vec<VideoFormat>) -> Result<Self> {
        if version != VERSION {
            return Err(invalid("unsupported media format version"));
        }
        Self::new(formats)
    }
    pub fn new(mut formats: Vec<VideoFormat>) -> Result<Self> {
        if formats.len() > MAX_FORMATS {
            return Err(invalid("too many discrete video formats"));
        }
        for format in &formats {
            format.validate()?;
        }
        formats.sort_unstable();
        // Duplicate wire entries are rejected, not silently laundered.
        if formats.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("duplicate discrete video format"));
        }
        Ok(Self(formats))
    }
    pub fn formats(&self) -> &[VideoFormat] {
        &self.0
    }
    pub fn contains(&self, format: &VideoFormat) -> bool {
        self.0.binary_search(format).is_ok()
    }
    pub fn intersection(&self, decoder: &Self) -> Self {
        Self(
            self.0
                .iter()
                .copied()
                .filter(|f| decoder.contains(f))
                .collect(),
        )
    }
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(SET_DOMAIN);
        hash.update(VERSION.to_be_bytes());
        hash.update((self.0.len() as u32).to_be_bytes());
        for format in &self.0 {
            hash.update(format.canonical());
        }
        hash.finalize().into()
    }
    /// Preferences are ordered exact configurations, never unsigned widening.
    /// Empty/no-common sets return None; caller must perform explicit fallback.
    pub fn select(&self, preferences: &[VideoFormat]) -> Result<Option<VideoFormat>> {
        if preferences.len() > MAX_FORMATS {
            return Err(invalid("too many video preferences"));
        }
        for format in preferences {
            format.validate()?;
        }
        Ok(preferences
            .iter()
            .find(|format| self.contains(format))
            .copied())
    }
}

fn h264_limits(level: u8) -> Option<(u64, u64, u64)> {
    Some(match level {
        10 => (99, 1485, 64),
        11 => (396, 3000, 192),
        12 => (396, 6000, 384),
        13 | 20 => (396, 11880, if level == 13 { 768 } else { 2000 }),
        21 => (792, 19800, 4000),
        22 => (1620, 20250, 4000),
        30 => (1620, 40500, 10000),
        31 => (3600, 108000, 14000),
        32 => (5120, 216000, 20000),
        40 => (8192, 245760, 20000),
        41 => (8192, 245760, 50000),
        42 => (8704, 522240, 50000),
        50 => (22080, 589824, 135000),
        51 => (36864, 983040, 240000),
        52 => (36864, 2073600, 240000),
        _ => return None,
    })
}
fn hevc_limits(level: u8) -> Option<(u64, u64, u64, u64)> {
    // Restricted catalog: levels 1 through 6.2, conservative Main bitrate limits.
    Some(match level {
        30 => (36864, 552960, 128, 0),
        60 => (122880, 3686400, 1500, 0),
        63 => (245760, 7372800, 3000, 0),
        90 => (552960, 16588800, 6000, 0),
        93 => (983040, 33177600, 10000, 0),
        120 => (2228224, 66846720, 12000, 30000),
        123 => (2228224, 133693440, 20000, 50000),
        150 => (8912896, 267386880, 25000, 100000),
        153 => (8912896, 534773760, 40000, 160000),
        156 => (8912896, 1069547520, 60000, 240000),
        180 => (35651584, 1069547520, 60000, 240000),
        183 => (35651584, 2139095040, 120000, 480000),
        186 => (35651584, 4278190080, 240000, 800000),
        _ => return None,
    })
}

#[cfg(test)]
#[path = "media_format_tests.rs"]
mod tests;
