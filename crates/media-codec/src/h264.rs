//! Bounded Annex B baseline validation before passing untrusted bytes to a
//! platform decoder. In-band SPS dimensions cannot enlarge the agreed surface.
use std::{collections::BTreeMap, io};

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid bounded H.264 baseline access unit",
    )
}

pub(crate) fn nals(data: &[u8]) -> io::Result<Vec<&[u8]>> {
    if data.is_empty() || data.len() > 8 * 1024 * 1024 {
        return Err(invalid());
    }
    let mut starts = Vec::new();
    let mut index = 0;
    while index + 3 <= data.len() {
        let prefix = if data[index..].starts_with(&[0, 0, 0, 1]) {
            4
        } else if data[index..].starts_with(&[0, 0, 1]) {
            3
        } else {
            index += 1;
            continue;
        };
        if starts.len() == 256 {
            return Err(invalid());
        }
        starts.push((index, index + prefix));
        index += prefix;
    }
    if starts.is_empty() || data[..starts[0].0].iter().any(|byte| *byte != 0) {
        return Err(invalid());
    }
    let mut result = Vec::with_capacity(starts.len());
    for (i, (_, start)) in starts.iter().enumerate() {
        let mut end = starts.get(i + 1).map_or(data.len(), |value| value.0);
        while end > *start && data[end - 1] == 0 {
            end -= 1;
        }
        if end <= *start || data[*start] & 0x80 != 0 {
            return Err(invalid());
        }
        result.push(&data[*start..end]);
    }
    Ok(result)
}

struct Bits {
    bytes: Vec<u8>,
    position: usize,
}
impl Bits {
    fn new(nal: &[u8], maximum: usize) -> io::Result<Self> {
        if nal.len() < 2 || nal.len() > maximum {
            return Err(invalid());
        }
        let mut bytes = Vec::with_capacity(nal.len() - 1);
        let mut zeros = 0;
        for (index, byte) in nal[1..].iter().copied().enumerate() {
            if zeros >= 2 {
                if byte == 3 {
                    if nal.get(index + 2).is_none_or(|next| *next > 3) {
                        return Err(invalid());
                    }
                    zeros = 0;
                    continue;
                }
                if byte <= 2 {
                    return Err(invalid());
                }
            }
            bytes.push(byte);
            zeros = if byte == 0 { zeros + 1 } else { 0 };
        }
        Ok(Self { bytes, position: 0 })
    }
    fn read(&mut self, count: usize) -> io::Result<u32> {
        if count > 32 || self.position + count > self.bytes.len() * 8 {
            return Err(invalid());
        }
        let mut value = 0;
        for _ in 0..count {
            value = (value << 1)
                | u32::from((self.bytes[self.position / 8] >> (7 - self.position % 8)) & 1);
            self.position += 1;
        }
        Ok(value)
    }
    fn ue(&mut self, maximum: u32) -> io::Result<u32> {
        let mut zeros = 0;
        while self.read(1)? == 0 {
            zeros += 1;
            if zeros > 24 {
                return Err(invalid());
            }
        }
        let value = ((1u32 << zeros) - 1) + self.read(zeros)?;
        if value > maximum {
            return Err(invalid());
        }
        Ok(value)
    }
}

/// Actual SPS bytes, suitable for SDP profile-level-id after a real probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H264SpsInfo {
    pub profile_idc: u8,
    pub constraints: u8,
    pub level_idc: u8,
}
impl H264SpsInfo {
    pub fn profile_level_id(self) -> String {
        format!(
            "{:02x}{:02x}{:02x}",
            self.profile_idc, self.constraints, self.level_idc
        )
    }
    pub fn is_constrained_baseline(self) -> bool {
        self.profile_idc == 66 && self.constraints & 0x40 != 0 && self.constraints & 3 == 0
    }
}

/// H.264 Baseline limits agreed before creating the stream. Level 1b is not
/// supported; it needs constraint_set3 interpretation rather than numeric order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H264EncodingLimits {
    pub max_level_idc: u8,
    pub require_constrained_baseline: bool,
}
impl H264EncodingLimits {
    pub fn validate_config(self, config: crate::VideoConfig) -> io::Result<()> {
        let (max_fs, max_mbps, max_kbps): (u64, u64, u32) = match self.max_level_idc {
            10 => (99, 1485, 64),
            11 => (396, 3000, 192),
            12 => (396, 6000, 384),
            13 => (396, 11880, 768),
            20 => (396, 11880, 2000),
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
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported H.264 level",
                ));
            }
        };
        let width_mbs = u64::from(config.width).div_ceil(16);
        let height_mbs = u64::from(config.height).div_ceil(16);
        let fs = width_mbs * height_mbs;
        if !config.width.is_multiple_of(2)
            || !config.height.is_multiple_of(2)
            || fs == 0
            || fs > max_fs
            || fs * u64::from(config.fps) > max_mbps
            || width_mbs * width_mbs > max_fs * 8
            || height_mbs * height_mbs > max_fs * 8
            || !(1..=120).contains(&config.fps)
            || config.width > 8192
            || config.height > 8192
            || u64::from(config.width) * u64::from(config.height) * 4 > 64 * 1024 * 1024
            || !(64..=100_000).contains(&config.bitrate_kbps)
            || config.bitrate_kbps > max_kbps
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target exceeds negotiated H.264 level",
            ));
        }
        Ok(())
    }
    pub fn validate_sps(self, info: H264SpsInfo) -> io::Result<()> {
        if !matches!(
            info.level_idc,
            10 | 11 | 12 | 13 | 20 | 21 | 22 | 30 | 31 | 32 | 40 | 41 | 42 | 50 | 51 | 52
        ) || info.profile_idc != 66
            || info.constraints & 3 != 0
            || (self.require_constrained_baseline && !info.is_constrained_baseline())
            || info.level_idc > self.max_level_idc
            || (info.level_idc == 11 && info.constraints & 0x10 != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SPS exceeds negotiated H.264 profile/level",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct H264Validator {
    width: u32,
    height: u32,
    sps: BTreeMap<u32, Vec<u8>>,
    pps: BTreeMap<u32, (u32, Vec<u8>)>,
    started: bool,
    limits: Option<H264EncodingLimits>,
    info: Option<H264SpsInfo>,
}
#[derive(Clone, Copy, Debug)]
pub struct H264AccessUnit {
    pub keyframe: bool,
    pub sps: Option<H264SpsInfo>,
}
impl H264Validator {
    #[cfg(windows)]
    pub(crate) fn reset_for_keyframe(&mut self) {
        self.sps.clear();
        self.pps.clear();
        self.started = false;
        self.info = None;
    }
    pub fn new(width: u32, height: u32) -> io::Result<Self> {
        if width == 0
            || height == 0
            || !width.is_multiple_of(2)
            || !height.is_multiple_of(2)
            || width > 8192
            || height > 8192
            || u64::from(width) * u64::from(height) * 4 > 64 * 1024 * 1024
        {
            return Err(invalid());
        }
        Ok(Self {
            width,
            height,
            sps: BTreeMap::new(),
            pps: BTreeMap::new(),
            started: false,
            limits: None,
            info: None,
        })
    }
    pub fn with_limits(width: u32, height: u32, limits: H264EncodingLimits) -> io::Result<Self> {
        let mut validator = Self::new(width, height)?;
        validator.limits = Some(limits);
        Ok(validator)
    }
    pub fn sps_info(&self) -> Option<H264SpsInfo> {
        self.info
    }
    pub fn validate(&mut self, data: &[u8]) -> io::Result<H264AccessUnit> {
        // A rejected packet must not leave a partially updated parameter table.
        let mut next = self.clone();
        let mut keyframe = None;
        for nal in nals(data)? {
            match nal[0] & 31 {
                7 => {
                    let id = next.validate_sps(nal).map_err(|error| {
                        io::Error::new(error.kind(), format!("H.264 SPS: {error}"))
                    })?;
                    if next.sps.get(&id).is_some_and(|old| old != nal) {
                        return Err(invalid());
                    }
                    let mut bits = Bits::new(nal, 4096)?;
                    let info = H264SpsInfo {
                        profile_idc: bits.read(8)? as u8,
                        constraints: bits.read(8)? as u8,
                        level_idc: bits.read(8)? as u8,
                    };
                    if let Some(limits) = next.limits {
                        limits.validate_sps(info)?;
                    }
                    if next.info.is_some_and(|old| old != info) {
                        return Err(invalid());
                    }
                    next.info = Some(info);
                    next.sps.insert(id, nal.to_vec());
                }
                8 => {
                    let mut bits = Bits::new(nal, 4096)?;
                    let id = bits.ue(31)?;
                    let sps = bits.ue(31)?;
                    // Baseline: no CABAC, field pictures or slice groups/FMO.
                    if !next.sps.contains_key(&sps)
                        || bits.read(1)? != 0
                        || bits.read(1)? != 0
                        || bits.ue(0)? != 0
                        || next.pps.get(&id).is_some_and(|old| old.1 != nal)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "unsupported H.264 PPS",
                        ));
                    }
                    next.pps.insert(id, (sps, nal.to_vec()));
                }
                kind @ (1 | 5) => {
                    // Only the bounded slice header prefix is needed here.
                    let mut prefix = nal.len().min(64);
                    // Include the byte after an emulation-prevention marker
                    // when the bounded header prefix ends at that marker.
                    if prefix < nal.len() && nal[prefix - 1] == 3 {
                        prefix += 1;
                    }
                    let mut bits = Bits::new(&nal[..prefix], 65)?;
                    bits.ue(262_143)?;
                    if !matches!(bits.ue(9)? % 5, 0 | 2) {
                        return Err(invalid());
                    }
                    let pps = bits.ue(31)?;
                    if !next.pps.contains_key(&pps)
                        || keyframe.is_some_and(|old| old != (kind == 5))
                    {
                        return Err(invalid());
                    }
                    keyframe = Some(kind == 5);
                }
                6 | 9 | 10 | 11 | 12 => {}
                _ => return Err(invalid()),
            }
        }
        let keyframe = keyframe.ok_or_else(invalid)?;
        if !next.started && !keyframe {
            return Err(invalid());
        }
        next.started = true;
        *self = next;
        Ok(H264AccessUnit {
            keyframe,
            sps: self.info,
        })
    }
    fn validate_sps(&self, nal: &[u8]) -> io::Result<u32> {
        let mut bits = Bits::new(nal, 4096)?;
        if bits.read(8)? != 66
            || bits.read(8)? & 3 != 0
            || !matches!(
                bits.read(8)?,
                10 | 11 | 12 | 13 | 20 | 21 | 22 | 30 | 31 | 32 | 40 | 41 | 42 | 50 | 51 | 52
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported profile or level",
            ));
        }
        let id = bits.ue(31)?;
        bits.ue(12)?; // log2_max_frame_num_minus4
        match bits.ue(2)? {
            0 => {
                bits.ue(12)?;
            }
            2 => {}
            // POC type 1 has signed offsets and a reference cycle; this product
            // uses the non-reordering baseline subset and rejects it.
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported H.264 picture order count",
                ));
            }
        }
        bits.ue(4).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "reference surface budget exceeded",
            )
        })?;
        bits.read(1)?; // gaps_in_frame_num_value_allowed_flag
        let coded_width = (bits.ue(511)? + 1) * 16;
        let coded_height = (bits.ue(511)? + 1) * 16;
        if bits.read(1)? != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "interlaced H.264 unsupported",
            ));
        }
        bits.read(1)?; // direct_8x8_inference_flag
        let (left, right, top, bottom) = if bits.read(1)? != 0 {
            (
                bits.ue(4096)?,
                bits.ue(4096)?,
                bits.ue(4096)?,
                bits.ue(4096)?,
            )
        } else {
            (0, 0, 0, 0)
        };
        // Baseline fixes chroma_format_idc=1, 8-bit and crop units to 2x2.
        if coded_width.checked_sub((left + right) * 2) != Some(self.width)
            || coded_height.checked_sub((top + bottom) * 2) != Some(self.height)
            || u64::from(coded_width) * u64::from(coded_height) * 4 > 65 * 1024 * 1024
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "H.264 geometry differs from the negotiated surface",
            ));
        }
        bits.read(1)?; // vui_parameters_present_flag must at least be present
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Build just the tested baseline SPS header, including rbsp trailing bits.
    fn sps(width_mbs: u32, height_mbs: u32, profile: u8, refs: u32) -> Vec<u8> {
        let mut bits = String::new();
        for byte in [profile, 0xc0, 31] {
            bits.push_str(&format!("{byte:08b}"));
        }
        for value in [0, 0, 2, refs] {
            ue(&mut bits, value);
        }
        bits.push('0');
        ue(&mut bits, width_mbs);
        ue(&mut bits, height_mbs);
        bits.push_str("11001");
        while !bits.len().is_multiple_of(8) {
            bits.push('0');
        }
        let mut bytes = vec![0, 0, 0, 1, 0x67];
        for part in bits.as_bytes().chunks(8) {
            let value = part.iter().fold(0, |value, bit| value * 2 + (bit - b'0'));
            if bytes.ends_with(&[0, 0]) && value <= 3 {
                bytes.push(3);
            }
            bytes.push(value);
        }
        bytes
    }
    fn ue(bits: &mut String, value: u32) {
        let value = format!("{:b}", value + 1);
        bits.push_str(&"0".repeat(value.len() - 1));
        bits.push_str(&value);
    }
    #[test]
    fn geometry_profile_references_and_initial_idr_are_enforced() -> io::Result<()> {
        let mut valid = sps(19, 14, 66, 1);
        valid.extend_from_slice(&[0, 0, 1, 0x68, 0xce, 0x38, 0x80, 0, 0, 1, 0x65, 0xb8, 0x40]);
        let mut parser = H264Validator::new(320, 240)?;
        assert!(parser.validate(&valid)?.keyframe);
        assert!(!parser.validate(&[0, 0, 1, 0x41, 0xe0])?.keyframe);
        assert!(H264Validator::new(640, 480)?.validate(&valid).is_err());
        for invalid_sps in [
            sps(511, 511, 66, 1),
            sps(19, 14, 100, 1),
            sps(19, 14, 66, 16),
        ] {
            assert!(
                H264Validator::new(320, 240)?
                    .validate(&invalid_sps)
                    .is_err()
            );
        }
        assert!(
            H264Validator::new(320, 240)?
                .validate(&[0, 0, 1, 0x41, 0xe0])
                .is_err()
        );
        assert!(parser.validate(&[0, 0, 1, 0x41, 0xa0]).is_err()); // B slice
        assert!(parser.validate(&[0, 0, 1, 0xe5, 0xb8]).is_err()); // forbidden bit
        Ok(())
    }
    #[test]
    fn actual_sps_identity_and_negotiated_target_limits_are_enforced() -> io::Result<()> {
        let limits = H264EncodingLimits {
            max_level_idc: 31,
            require_constrained_baseline: true,
        };
        let target = crate::VideoConfig {
            width: 1280,
            height: 720,
            fps: 30,
            bitrate_kbps: 4000,
        };
        limits.validate_config(target)?;
        assert!(
            limits
                .validate_config(crate::VideoConfig { fps: 60, ..target })
                .is_err()
        );
        assert!(
            limits
                .validate_config(crate::VideoConfig {
                    width: 1920,
                    height: 1080,
                    ..target
                })
                .is_err()
        );
        assert!(
            limits
                .validate_config(crate::VideoConfig {
                    bitrate_kbps: 14001,
                    ..target
                })
                .is_err()
        );
        let mut packet = sps(19, 14, 66, 1);
        packet.extend_from_slice(&[0, 0, 1, 0x68, 0xce, 0x38, 0x80, 0, 0, 1, 0x65, 0xb8, 0x40]);
        let unit = H264Validator::with_limits(320, 240, limits)?.validate(&packet)?;
        let info = unit.sps.ok_or_else(invalid)?;
        assert_eq!(info.profile_level_id(), "42c01f");
        assert!(info.is_constrained_baseline());
        let mut too_high = packet.clone();
        too_high[7] = 40;
        assert!(
            H264Validator::with_limits(320, 240, limits)?
                .validate(&too_high)
                .is_err()
        );
        let mut baseline_only = packet;
        baseline_only[6] = 0x80;
        assert!(
            H264Validator::new(320, 240)?
                .validate(&baseline_only)
                .is_ok()
        );
        assert!(
            H264Validator::with_limits(320, 240, limits)?
                .validate(&baseline_only)
                .is_err()
        );
        assert!(
            limits
                .validate_sps(H264SpsInfo {
                    level_idc: 11,
                    constraints: 0xd0,
                    ..info
                })
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn malformed_annex_b_and_parameter_growth_are_bounded() {
        assert!(nals(&[1, 2, 3]).is_err());
        assert!(nals(&[0, 0, 1]).is_err());
        assert!(nals(&[0, 0, 1, 0x67].repeat(257)).is_err());
        assert!(Bits::new(&[0x67, 0, 0, 3, 5], 4096).is_err());
        assert!(Bits::new(&[0x67, 0, 0, 3], 4096).is_err());
    }
}
