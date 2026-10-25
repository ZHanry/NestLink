//! Explicit local operator policy for one internal product candidate.
//! Configuration is not probe evidence, an issuer, or additional permit authority.
use crate::media_format::{BitDepth, Chroma, Codec, FormatSet, Profile, VideoFormat};
use crate::{ContractError, ErrorCode, PermitClaims, valid_id};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalSoftwareMediaCandidate {
    pub deployment_id: String,
    pub account_id: String,
    pub controller_device_id: String,
    pub host_device_id: String,
    /// Exact canonical observed format, not a width/FPS preset or capability range.
    pub format: Vec<u8>,
    pub format_sha256: [u8; 32],
}
fn denied() -> ContractError {
    ContractError::new(
        ErrorCode::PlatformUnsupported,
        "internal software media candidate policy mismatch",
    )
}
impl InternalSoftwareMediaCandidate {
    pub fn validate(&self) -> Result<VideoFormat, ContractError> {
        if [
            &self.deployment_id,
            &self.account_id,
            &self.controller_device_id,
            &self.host_device_id,
        ]
        .iter()
        .any(|id| !valid_id(id))
            || self.controller_device_id == self.host_device_id
        {
            return Err(denied());
        }
        let format = VideoFormat::decode(&self.format)?;
        if format.codec != Codec::H264
            || format.profile != Profile::H264Baseline
            || format.chroma != Chroma::Yuv420
            || format.bit_depth != BitDepth::Eight
            || format.frame_rate.denominator != 1
            || !(1..=120).contains(&format.frame_rate.numerator)
            || !(64..=100_000).contains(&format.max_kbps)
            || format.digest()? != self.format_sha256
        {
            return Err(denied());
        }
        Ok(format)
    }
    pub fn authorize_scope(
        &self,
        deployment: &str,
        account: &str,
        controller: &str,
        host: &str,
        formats: &[Vec<u8>],
    ) -> Result<(), ContractError> {
        self.validate()?;
        if deployment != self.deployment_id
            || account != self.account_id
            || controller != self.controller_device_id
            || host != self.host_device_id
            || formats != std::slice::from_ref(&self.format)
        {
            return Err(denied());
        }
        Ok(())
    }
    /// Check the actual signed-in local host and reviewed frozen scope before
    /// a provider publication or approval signature may be dispatched.
    pub fn authorize_host_approval(
        &self,
        deployment: &str,
        account: &str,
        local_host: &str,
        controller: &str,
        host: &str,
        formats: &[Vec<u8>],
    ) -> Result<(), ContractError> {
        self.authorize_scope(deployment, account, controller, host, formats)?;
        if local_host != self.host_device_id {
            return Err(denied());
        }
        Ok(())
    }
    pub fn authorize_permit(&self, claims: &PermitClaims) -> Result<(), ContractError> {
        self.authorize_scope(
            &claims.deployment_id,
            &claims.account_id,
            &claims.controller_device_id,
            &claims.host_device_id,
            &claims.media_formats,
        )?;
        if !claims
            .required_capabilities
            .iter()
            .any(|value| value == crate::media::H264_CAPABILITY)
        {
            return Err(denied());
        }
        let signed = crate::media_authority::permit_formats(claims)?.ok_or_else(denied)?;
        if signed != FormatSet::new(vec![self.validate()?])? {
            return Err(denied());
        }
        Ok(())
    }
    pub fn authorize_announcement(
        &self,
        value: &crate::media_authority::MediaAnnouncement,
        now_ms: u64,
    ) -> Result<(), ContractError> {
        value.validate(now_ms)?;
        let expected = match value.direction {
            crate::media_authority::MediaDirection::Encode => &self.host_device_id,
            crate::media_authority::MediaDirection::Decode => &self.controller_device_id,
        };
        if &value.device_id != expected
            || value.probe.backend != "cpu-software"
            || value.probe.adapter_luid.is_some()
            || value.probe.driver_version.is_some()
            || value.formats.as_slice() != std::slice::from_ref(&self.format)
        {
            return Err(denied());
        }
        self.validate()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn internal_candidate_policy_requires_every_exact_field_and_rejects_non_h264()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::media_format::FrameRate;
        let format = VideoFormat::legacy_h264(31, 320, 240, FrameRate::new(30, 1)?, 2000)?;
        let policy = InternalSoftwareMediaCandidate {
            deployment_id: "11111111-1111-4111-8111-111111111111".into(),
            account_id: "22222222-2222-4222-8222-222222222222".into(),
            controller_device_id: "33333333-3333-4333-8333-333333333333".into(),
            host_device_id: "44444444-4444-4444-8444-444444444444".into(),
            format: format.encode()?,
            format_sha256: format.digest()?,
        };
        policy.validate()?;
        // Actual principal/local identity are separate inputs; policy values
        // cannot stand in for the caller's current authenticated account/key.
        policy.authorize_host_approval(
            &policy.deployment_id,
            &policy.account_id,
            &policy.host_device_id,
            &policy.controller_device_id,
            &policy.host_device_id,
            std::slice::from_ref(&policy.format),
        )?;
        for wrong in 0..6 {
            let deployment = if wrong == 0 {
                &policy.account_id
            } else {
                &policy.deployment_id
            };
            let account = if wrong == 1 {
                &policy.deployment_id
            } else {
                &policy.account_id
            };
            let local = if wrong == 2 {
                &policy.controller_device_id
            } else {
                &policy.host_device_id
            };
            let controller = if wrong == 3 {
                &policy.host_device_id
            } else {
                &policy.controller_device_id
            };
            let host = if wrong == 4 {
                &policy.controller_device_id
            } else {
                &policy.host_device_id
            };
            let formats = if wrong == 5 {
                Vec::new()
            } else {
                vec![policy.format.clone()]
            };
            assert!(
                policy
                    .authorize_host_approval(deployment, account, local, controller, host, &formats)
                    .is_err()
            );
        }
        let serialized = serde_json::to_value(&policy)?;
        for field in [
            "deployment_id",
            "account_id",
            "controller_device_id",
            "host_device_id",
            "format",
            "format_sha256",
        ] {
            let mut missing = serialized.clone();
            if let Some(object) = missing.as_object_mut() {
                object.remove(field);
            }
            assert!(serde_json::from_value::<InternalSoftwareMediaCandidate>(missing).is_err());
        }
        let mut extra = serialized;
        extra["enable_all"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<InternalSoftwareMediaCandidate>(extra).is_err());
        let mut bad = policy.clone();
        bad.format_sha256[0] ^= 1;
        assert!(bad.validate().is_err());
        let mut bad = policy.clone();
        bad.host_device_id = bad.controller_device_id.clone();
        assert!(bad.validate().is_err());
        let vp8 = VideoFormat::legacy_vp8(320, 240, FrameRate::new(30, 1)?, 2000)?;
        let mut bad = policy;
        bad.format = vp8.encode()?;
        bad.format_sha256 = vp8.digest()?;
        assert!(bad.validate().is_err());
        Ok(())
    }
}
