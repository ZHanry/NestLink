//! Bounded RFC 6184 subset shared by browser offers and native answerers.
use super::invalid;
use crate::ContractError;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoFormat {
    Vp8,
    H264(H264Format),
}

/// Read the already validated, signed description without rewriting it.
pub fn offered_formats(sdp: &str) -> Result<Vec<(u8, VideoFormat)>, ContractError> {
    if sdp.len() > 65_536 || sdp.contains('\0') {
        return Err(invalid("invalid SDP budget"));
    }
    let mut result = Vec::new();
    let mut section = false;
    let mut payloads = Vec::new();
    let mut mappings = BTreeMap::new();
    let mut formats = BTreeMap::new();
    let mut videos = 0;
    for line in sdp.lines() {
        if line.starts_with("m=") {
            section = line.starts_with("m=video ");
            if section {
                videos += 1;
                if videos != 1 {
                    return Err(invalid("multiple video sections unsupported"));
                }
                payloads = line.split_ascii_whitespace().skip(3).collect();
            }
        } else if section {
            if let Some(value) = line.strip_prefix("a=rtpmap:") {
                let (pt, mapping) = value
                    .split_once(' ')
                    .ok_or_else(|| invalid("invalid RTP mapping"))?;
                if mappings.insert(pt, mapping).is_some() {
                    return Err(invalid("duplicate RTP mapping"));
                }
            }
            if let Some(value) = line.strip_prefix("a=fmtp:") {
                let (pt, fmtp) = value
                    .split_once(' ')
                    .ok_or_else(|| invalid("invalid RTP format"))?;
                if formats.insert(pt, fmtp).is_some() {
                    return Err(invalid("duplicate RTP format"));
                }
            }
        }
    }
    for pt in payloads {
        let number = pt
            .parse::<u8>()
            .ok()
            .filter(|number| *number <= 127)
            .ok_or_else(|| invalid("invalid RTP payload"))?;
        if let Some(mapping) = mappings.get(pt) {
            if mapping.eq_ignore_ascii_case("vp8/90000") {
                result.push((number, VideoFormat::Vp8));
            } else if mapping.eq_ignore_ascii_case("h264/90000")
                && let Some(format) = H264Format::parse(formats.get(pt).copied().unwrap_or(""))?
            {
                result.push((number, VideoFormat::H264(format)));
            }
        }
    }
    Ok(result)
}

/// Enforce the offered payload/profile/level binding before installing a signed
/// answer. This product deliberately negotiates symmetric level bounds.
pub fn validate_answer(offer: &str, answer: &str) -> Result<(), ContractError> {
    let offered = offered_formats(offer)?;
    let answered = offered_formats(answer)?;
    if answered.len() != 1
        || !answered.iter().all(|(payload, actual)| {
            offered.iter().any(|(proposed_payload, proposed)| {
                payload == proposed_payload
                    && match (*proposed, *actual) {
                        (VideoFormat::Vp8, VideoFormat::Vp8) => true,
                        (VideoFormat::H264(proposed), VideoFormat::H264(actual)) => {
                            proposed.profile == actual.profile
                                && actual.level_idc <= proposed.level_idc
                        }
                        _ => false,
                    }
            })
        })
    {
        return Err(invalid(
            "video answer exceeds offered payload/profile/level",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H264Profile {
    Baseline,
    ConstrainedBaseline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H264Format {
    pub profile: H264Profile,
    pub profile_idc: u8,
    pub constraints: u8,
    pub level_idc: u8,
    pub level_asymmetry_allowed: bool,
}

impl H264Format {
    /// Only non-interleaved packetization is supported. Missing mode means 0.
    pub fn parse(fmtp: &str) -> Result<Option<Self>, ContractError> {
        let mut values = BTreeMap::new();
        for field in fmtp.split(';').filter(|field| !field.trim().is_empty()) {
            let (key, value) = field
                .trim()
                .split_once('=')
                .ok_or_else(|| invalid("malformed H.264 format parameter"))?;
            let key = key.trim().to_ascii_lowercase();
            if values.insert(key, value.trim()).is_some() {
                return Err(invalid("duplicate H.264 format parameter"));
            }
        }
        // Do not silently ignore receiver limits (max-fs/max-mbps/max-br) or
        // out-of-band parameter sets. This implementation negotiates only the
        // small in-band subset whose constraints it enforces end to end.
        if values.keys().any(|key| {
            !matches!(
                key.as_str(),
                "packetization-mode" | "profile-level-id" | "level-asymmetry-allowed"
            )
        }) {
            return Ok(None);
        }
        let mode = values.get("packetization-mode").copied().unwrap_or("0");
        if !matches!(mode, "0" | "1" | "2") {
            return Err(invalid("invalid H.264 packetization mode"));
        }
        let asymmetry = values
            .get("level-asymmetry-allowed")
            .copied()
            .unwrap_or("0");
        if !matches!(asymmetry, "0" | "1") {
            return Err(invalid("invalid H.264 level asymmetry"));
        }
        let hex = values.get("profile-level-id").copied().unwrap_or("42e01f");
        if hex.len() != 6 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid("invalid H.264 profile level identifier"));
        }
        let number = u32::from_str_radix(hex, 16)
            .map_err(|_| invalid("invalid H.264 profile level identifier"))?;
        let profile_idc = (number >> 16) as u8;
        let constraints = (number >> 8) as u8;
        let level_idc = number as u8;
        // RFC 6184 table 5 profile patterns. Level 1b requires separate ordering
        // and is deliberately excluded from this small product profile.
        let profile = match (profile_idc, constraints) {
            (0x42, bits) if bits & 0x4f == 0x40 => H264Profile::ConstrainedBaseline,
            (0x4d, bits) if bits & 0x8f == 0x80 => H264Profile::ConstrainedBaseline,
            (0x58, bits) if bits & 0xcf == 0xc0 => H264Profile::ConstrainedBaseline,
            (0x42, bits) if bits & 0x4f == 0 => H264Profile::Baseline,
            (0x58, bits) if bits & 0xcf == 0x80 => H264Profile::Baseline,
            _ => return Ok(None),
        };
        if mode != "1"
            || level_limits(level_idc).is_none()
            || (level_idc == 11 && constraints & 0x10 != 0)
        {
            return Ok(None);
        }
        Ok(Some(Self {
            profile,
            profile_idc,
            constraints,
            level_idc,
            level_asymmetry_allowed: asymmetry == "1",
        }))
    }

    pub fn fmtp(self) -> String {
        format!(
            "level-asymmetry-allowed=0;packetization-mode=1;profile-level-id={:02x}{:02x}{:02x}",
            self.profile_idc, self.constraints, self.level_idc
        )
    }

    /// Conservative symmetric level bound; every dimension is coded geometry.
    pub fn supports(self, width: u32, height: u32, fps: u32, kbps: u32) -> bool {
        let Some((max_fs, max_mbps, max_kbps)) = level_limits(self.level_idc) else {
            return false;
        };
        let columns = u64::from(width).div_ceil(16);
        let rows = u64::from(height).div_ceil(16);
        width > 0
            && height > 0
            && fps > 0
            && kbps > 0
            && columns * rows <= max_fs
            && columns * rows * u64::from(fps) <= max_mbps
            && columns * columns <= max_fs * 8
            && rows * rows <= max_fs * 8
            && u64::from(kbps) <= max_kbps
    }
}

fn level_limits(level: u8) -> Option<(u64, u64, u64)> {
    Some(match level {
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
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_answers_cannot_change_payload_profile_or_raise_level() -> Result<(), ContractError> {
        let offer = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96 102\r\na=rtpmap:96 VP8/90000\r\na=rtpmap:102 H264/90000\r\na=fmtp:102 packetization-mode=1;profile-level-id=42e029\r\n";
        let answer = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 102\r\na=rtpmap:102 H264/90000\r\na=fmtp:102 packetization-mode=1;profile-level-id=42e028\r\n";
        validate_answer(offer, answer)?;
        assert!(validate_answer(offer, &answer.replace("42e028", "42e02a")).is_err());
        assert!(validate_answer(offer, &answer.replace("42e028", "420028")).is_err());
        assert!(validate_answer(offer, &answer.replace("102", "104")).is_err());
        assert!(validate_answer(offer, offer).is_err());
        Ok(())
    }

    #[test]
    fn profile_patterns_modes_and_duplicates() -> Result<(), ContractError> {
        for hex in ["42e01f", "4d801f", "58c01f"] {
            let parsed =
                H264Format::parse(&format!("packetization-mode=1;profile-level-id={hex}"))?;
            assert_eq!(
                parsed.map(|value| value.profile),
                Some(H264Profile::ConstrainedBaseline)
            );
        }
        assert!(H264Format::parse("profile-level-id=42e01f")?.is_none());
        assert!(H264Format::parse("packetization-mode=1;profile-level-id=64001f")?.is_none());
        assert!(H264Format::parse("packetization-mode=1;profile-level-id=42f00b")?.is_none());
        assert!(H264Format::parse("packetization-mode=1;packetization-mode=1").is_err());
        assert!(H264Format::parse("packetization-mode=1;profile-level-id=xyzxyz").is_err());
        Ok(())
    }

    #[test]
    fn levels_bound_geometry_rate_and_bitrate() -> Result<(), ContractError> {
        let level31 = H264Format::parse("packetization-mode=1;profile-level-id=42e01f")?
            .ok_or_else(|| invalid("test format missing"))?;
        assert!(level31.supports(1280, 720, 30, 4000));
        assert!(!level31.supports(1920, 1080, 30, 4000));
        assert!(!level31.supports(1280, 720, 60, 4000));
        assert!(!level31.supports(1280, 720, 30, 14001));
        assert!(!level31.supports(65535, 1, 1, 64));
        Ok(())
    }
}
