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

#[derive(Clone, Debug)]
pub struct H264Validator {
    width: u32,
    height: u32,
    sps: BTreeMap<u32, Vec<u8>>,
    pps: BTreeMap<u32, (u32, Vec<u8>)>,
    started: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct H264AccessUnit {
    pub keyframe: bool,
}
impl H264Validator {
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
        })
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
        Ok(H264AccessUnit { keyframe })
    }
    fn validate_sps(&self, nal: &[u8]) -> io::Result<u32> {
        let mut bits = Bits::new(nal, 4096)?;
        if bits.read(8)? != 66 || bits.read(8)? & 3 != 0 || bits.read(8)? > 52 {
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
    fn malformed_annex_b_and_parameter_growth_are_bounded() {
        assert!(nals(&[1, 2, 3]).is_err());
        assert!(nals(&[0, 0, 1]).is_err());
        assert!(nals(&[0, 0, 1, 0x67].repeat(257)).is_err());
        assert!(Bits::new(&[0x67, 0, 0, 3, 5], 4096).is_err());
        assert!(Bits::new(&[0x67, 0, 0, 3], 4096).is_err());
    }
}
