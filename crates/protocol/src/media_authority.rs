//! Signed finite media scope. Data validation never attests to a local probe.
use crate::media_format::{Codec, FormatSet, VideoFormat};
use crate::{ContractError, ErrorCode, PermitClaims};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
pub const FORMAT_CAPABILITY: &str = "native-media-format-v2";
pub const FORMAT_VERSION: u32 = 2;
/// Remains false until both direction probes, selection/ACK, IPC and producers
/// enforce this scope. A catalog or successful test never enables issuance.
pub const PRODUCTION_ISSUANCE_ENABLED: bool = false;
type Result<T> = std::result::Result<T, ContractError>;
fn invalid(reason: &'static str) -> ContractError {
    ContractError::new(ErrorCode::InvalidMessage, reason)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireVideoFormat {
    pub canonical: Vec<u8>,
}
impl TryFrom<WireVideoFormat> for VideoFormat {
    type Error = ContractError;
    fn try_from(value: WireVideoFormat) -> Result<Self> {
        Self::decode(&value.canonical)
    }
}
impl TryFrom<VideoFormat> for WireVideoFormat {
    type Error = ContractError;
    fn try_from(value: VideoFormat) -> Result<Self> {
        Ok(Self {
            canonical: value.encode()?,
        })
    }
}

/// Canonical sorted exact configurations; empty is only legal for withdrawal.
pub fn decode_formats(wire: &[Vec<u8>], allow_empty: bool) -> Result<FormatSet> {
    if wire.len() > 64 || (!allow_empty && wire.is_empty()) {
        return Err(invalid("invalid media catalog count"));
    }
    let set = FormatSet::new(
        wire.iter()
            .map(|b| VideoFormat::decode(b))
            .collect::<Result<Vec<_>>>()?,
    )?;
    // First authority release supports only actual Baseline 8-bit 420 SDR H264.
    if set.formats().iter().any(|f| f.codec != Codec::H264) {
        return Err(invalid("authority codec not enabled"));
    }
    let encoded = set
        .formats()
        .iter()
        .map(|f| f.encode())
        .collect::<Result<Vec<_>>>()?;
    if encoded.as_slice() != wire {
        return Err(invalid("media catalog must be sorted and exact"));
    }
    Ok(set)
}
pub fn permit_formats(claims: &PermitClaims) -> Result<Option<FormatSet>> {
    let markers = claims
        .required_capabilities
        .iter()
        .filter(|s| s.as_str() == FORMAT_CAPABILITY)
        .count();
    if markers == 0 {
        if claims.media_format_version != 0
            || !claims.media_formats.is_empty()
            || !claims.media_format_sha256.is_empty()
        {
            return Err(invalid("media scope without required marker"));
        }
        return Ok(None);
    }
    if markers != 1 || claims.media_format_version != FORMAT_VERSION {
        return Err(invalid("unsupported media authority version"));
    }
    let set = decode_formats(&claims.media_formats, false)?;
    if claims.media_format_sha256.as_slice() != set.digest() {
        return Err(invalid("media scope digest mismatch"));
    }
    Ok(Some(set))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MediaDirection {
    Encode,
    Decode,
}
impl MediaDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encode => "encode",
            Self::Decode => "decode",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeIdentity {
    pub generation: u64,
    pub resource_id: String,
    pub backend: String,
    pub adapter_luid: Option<u64>,
    pub driver_version: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MediaAnnouncement {
    pub version: u32,
    pub device_id: String,
    pub direction: MediaDirection,
    pub revision: u64,
    pub expires_at_unix_ms: u64,
    pub probe: ProbeIdentity,
    pub formats: Vec<Vec<u8>>,
}
impl MediaAnnouncement {
    pub fn validate(&self, now_ms: u64) -> Result<FormatSet> {
        if self.version != FORMAT_VERSION
            || !crate::valid_id(&self.device_id)
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || self.probe.generation == 0
            || self.probe.generation > i64::MAX as u64
            || !crate::valid_id(&self.probe.resource_id)
            || self.expires_at_unix_ms <= now_ms
            || self.expires_at_unix_ms > now_ms.saturating_add(300_000)
        {
            return Err(invalid("invalid media announcement identity or lifetime"));
        }
        match self.probe.backend.as_str() {
            "cpu-software"
                if self.probe.adapter_luid.is_none() && self.probe.driver_version.is_none() => {}
            "cpu-hardware-readback" | "gpu-presenter"
                if self.probe.adapter_luid.is_some() && self.probe.driver_version.is_some() => {}
            _ => return Err(invalid("unbound media backend identity")),
        }
        decode_formats(&self.formats, true)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrozenMediaScope {
    pub version: u32,
    pub controller_revision: u64,
    pub host_revision: u64,
    pub formats: Vec<Vec<u8>>,
    pub sha256: Vec<u8>,
}
impl FrozenMediaScope {
    pub fn validate(&self) -> Result<FormatSet> {
        if self.version != FORMAT_VERSION
            || self.controller_revision == 0
            || self.host_revision == 0
        {
            return Err(invalid("invalid frozen media scope"));
        }
        let set = decode_formats(&self.formats, false)?;
        if self.sha256.as_slice() != set.digest() {
            return Err(invalid("frozen media digest mismatch"));
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media_format::FrameRate;
    fn format() -> Result<VideoFormat> {
        VideoFormat::legacy_h264(31, 320, 240, FrameRate::new(30, 1)?, 2000)
    }
    fn claims() -> Result<PermitClaims> {
        let set = FormatSet::new(vec![format()?])?;
        Ok(PermitClaims {
            media_format_version: 2,
            media_formats: vec![format()?.encode()?],
            media_format_sha256: set.digest().to_vec(),
            required_capabilities: vec![FORMAT_CAPABILITY.into()],
            ..Default::default()
        })
    }
    #[test]
    fn canonical_format_roundtrip_rejects_trailing_unknown_flags_and_nonreduced_rate() -> Result<()>
    {
        let bytes = format()?.encode()?;
        assert_eq!(bytes.len(), 57);
        assert_eq!(VideoFormat::decode(&bytes)?, format()?);
        for variant in 0..5 {
            let mut bad = bytes.clone();
            match variant {
                0 => bad.push(0),
                1 => bad[0] = 1,
                2 => bad[5] = 1,
                3 => bad[2] = 99,
                _ => {
                    bad[45..49].copy_from_slice(&60u32.to_be_bytes());
                    bad[49..53].copy_from_slice(&2u32.to_be_bytes());
                }
            }
            assert!(VideoFormat::decode(&bad).is_err());
        }
        Ok(())
    }
    #[test]
    fn signed_scope_cannot_omit_marker_duplicate_or_change_crop_and_digest() -> Result<()> {
        assert!(permit_formats(&PermitClaims::default())?.is_none());
        let good = claims()?;
        assert!(permit_formats(&good)?.is_some());
        for variant in 0..6 {
            let mut bad = good.clone();
            match variant {
                0 => bad.required_capabilities.clear(),
                1 => bad.media_format_version = 1,
                2 => bad.media_formats.clear(),
                3 => bad.media_format_sha256[0] ^= 1,
                4 => bad.media_formats.push(bad.media_formats[0].clone()),
                _ => bad.media_formats[0][32] ^= 2,
            }
            assert!(permit_formats(&bad).is_err());
        }
        Ok(())
    }
    #[test]
    fn announcement_withdrawal_is_explicit_and_backend_identity_is_not_defaulted() -> Result<()> {
        let mut a = MediaAnnouncement {
            version: 2,
            device_id: "11111111-1111-4111-8111-111111111111".into(),
            direction: MediaDirection::Decode,
            revision: 1,
            expires_at_unix_ms: 1100,
            probe: ProbeIdentity {
                generation: 1,
                resource_id: "22222222-1111-4111-8111-111111111111".into(),
                backend: "cpu-software".into(),
                adapter_luid: None,
                driver_version: None,
            },
            formats: vec![],
        };
        assert!(a.validate(1000)?.formats().is_empty());
        a.probe.backend = "gpu-presenter".into();
        assert!(a.validate(1000).is_err());
        a.probe.adapter_luid = Some(1);
        a.probe.driver_version = Some(1);
        assert!(a.validate(1000).is_ok());
        assert!(a.validate(1100).is_err());
        Ok(())
    }
}
