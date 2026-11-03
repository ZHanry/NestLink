//! Private local selection for the explicit v3-v6 production routes. Signed peer
//! fields and a remote announcement cannot create this local opt-in.
use super::*;
use nestlink_protocol::media_authority::{
    MediaAnnouncement, MediaDirection, ProbeIdentity, VP9_RGB444_FORMAT_VERSION,
    decode_formats_for_version, permit_formats,
};
use nestlink_protocol::media_format::FormatSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExplicitSelection {
    deployment: String,
    account: String,
    controller: String,
    host: String,
    session: String,
    resource: String,
    generation: u64,
    version: u32,
    formats: FormatSet,
}
impl ExplicitSelection {
    pub(super) fn formats(&self) -> &FormatSet {
        &self.formats
    }
    pub(super) fn authorize(
        &self,
        claims: &nestlink_protocol::PermitClaims,
    ) -> Result<(), ContractError> {
        if self.deployment != claims.deployment_id
            || self.account != claims.account_id
            || self.controller != claims.controller_device_id
            || self.host != claims.host_device_id
            || self.session != claims.session_id
            || self.resource != claims.resource_id
            || self.generation != claims.connection_generation
            || self.version != claims.media_format_version
            || permit_formats(claims)?.as_ref() != Some(&self.formats)
        {
            return Err(error(
                ErrorCode::IdentityMismatch,
                "explicit local media selection changed signed scope",
            ));
        }
        Ok(())
    }
    pub(super) fn check_probe(
        &self,
        direction: MediaDirection,
        probe: &ProbeIdentity,
    ) -> Result<(), ContractError> {
        let software = self.version == VP9_RGB444_FORMAT_VERSION;
        let backend = if software {
            "cpu-software"
        } else {
            match direction {
                MediaDirection::Encode => "gpu-hevc-encoder",
                MediaDirection::Decode => "gpu-hevc-decoder",
            }
        };
        if probe.backend != backend
            || probe.adapter_luid.is_some() == software
            || probe.driver_version.is_some() == software
        {
            return Err(error(
                ErrorCode::PlatformUnsupported,
                "explicit media local direction/backend/platform differs",
            ));
        }
        Ok(())
    }
}

impl MediaSessionBinding {
    /// Trusted local application selection only. The caller obtains these exact
    /// formats from its explicit configured provider, then retains its original
    /// probe and live execution fences. This value itself proves no execution.
    pub fn with_explicit_media_selection(
        mut self,
        formats: FormatSet,
        permit: &VerifiedPermit,
        local: &MediaAnnouncement,
        now_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let claims = permit.claims();
        let version = claims.media_format_version;
        let available = local.validate(now_unix_ms)?;
        if !(3..=6).contains(&version)
            || self.internal_candidate.is_some()
            || formats.formats().is_empty()
            || formats.formats().len() > 2
            || (version == VP9_RGB444_FORMAT_VERSION && formats.formats().len() != 1)
            || local.version != version
            || formats
                .formats()
                .iter()
                .any(|format| !available.formats().contains(format))
            || decode_formats_for_version(&self.formats, false, version)? != formats
            || self.probe != local.probe
            || self.device_id != local.device_id
            || self.direction != local.direction
            || self.revision != local.revision
        {
            return Err(error(
                ErrorCode::IdentityMismatch,
                "explicit media selection differs from exact local evidence",
            ));
        }
        let selection = ExplicitSelection {
            deployment: claims.deployment_id.clone(),
            account: claims.account_id.clone(),
            controller: claims.controller_device_id.clone(),
            host: claims.host_device_id.clone(),
            session: claims.session_id.clone(),
            resource: claims.resource_id.clone(),
            generation: claims.connection_generation,
            version,
            formats,
        };
        selection.authorize(claims)?;
        selection.check_probe(self.direction, &self.probe)?;
        self.explicit_selection = Some(selection);
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use nestlink_identity::{InstallationIdentity, PermitSigner, verify_permit};
    use nestlink_protocol::{PermitClaims, media_authority::*, media_format::*};
    use prost::Message;

    fn id(value: u8) -> String {
        format!("{value:08x}-1111-4111-8111-111111111111")
    }
    fn verified(signer: &PermitSigner, claims: &PermitClaims) -> VerifiedPermit {
        verify_permit(
            &signer.sign(claims).unwrap().encode_to_vec(),
            &signer.public_key(),
        )
        .unwrap()
    }
    fn format(version: u32, width: u32) -> VideoFormat {
        let fps = FrameRate::new(30, 1).unwrap();
        let mut ptl = [0; 12];
        ptl[0] = if version == 3 { 1 } else { 2 };
        ptl[11] = 120;
        match version {
            3 => VideoFormat::hevc_main8_observed(ptl, width, 240, fps, 4000).unwrap(),
            4 => VideoFormat::hevc_main10_observed(ptl, width, 240, fps, 4000).unwrap(),
            5 => VideoFormat::hevc_hdr10_observed(ptl, width, 240, fps, 4000).unwrap(),
            _ => VideoFormat::vp9_rgb444(width, 240, fps, 4000).unwrap(),
        }
    }
    #[test]
    fn explicit_v3_to_v6_require_local_selection_and_preserve_exact_scope_across_renewal() {
        for version in 3..=6 {
            for role in [EndpointRole::Host, EndpointRole::Controller] {
                let signer = PermitSigner::from_seed([1; 32]);
                let controller = InstallationIdentity::from_seed([2; 32]);
                let host = InstallationIdentity::from_seed([3; 32]);
                let formats = FormatSet::new(vec![format(version, 320)]).unwrap();
                let mut claims = PermitClaims {
                    schema_version: SCHEMA_VERSION,
                    deployment_id: id(1),
                    security_epoch: 1,
                    session_id: id(2),
                    account_id: id(3),
                    controller_device_id: id(4),
                    host_device_id: id(5),
                    controller_key_sha256: controller.fingerprint().to_vec(),
                    host_key_sha256: host.fingerprint().to_vec(),
                    resource_id: id(6),
                    permissions: vec![Permission::View as i32],
                    paths: vec![Path::Direct as i32],
                    policy_revision: 1,
                    connection_generation: 9,
                    lease_sequence: 1,
                    issued_at_unix_ms: 1_000_000,
                    expires_at_unix_ms: 1_015_000,
                    capability_sha256: vec![7; 32],
                    required_capabilities: vec![
                        "vp8".into(),
                        capability_for_version(version).unwrap().into(),
                    ],
                    media_format_version: version,
                    media_formats: vec![format(version, 320).encode().unwrap()],
                    media_format_sha256: formats.digest().to_vec(),
                };
                let frozen = FrozenMediaScope {
                    version,
                    controller_revision: 1,
                    host_revision: 1,
                    formats: claims.media_formats.clone(),
                    sha256: claims.media_format_sha256.clone(),
                };
                let direction = if role == EndpointRole::Host {
                    MediaDirection::Encode
                } else {
                    MediaDirection::Decode
                };
                let mut local = MediaAnnouncement {
                    version,
                    device_id: if role == EndpointRole::Host {
                        claims.host_device_id.clone()
                    } else {
                        claims.controller_device_id.clone()
                    },
                    direction,
                    revision: 1,
                    expires_at_unix_ms: 1_030_000,
                    probe: ProbeIdentity {
                        generation: 1,
                        resource_id: id(8),
                        backend: if version == 6 {
                            "cpu-software"
                        } else if role == EndpointRole::Host {
                            "gpu-hevc-encoder"
                        } else {
                            "gpu-hevc-decoder"
                        }
                        .into(),
                        adapter_luid: (version != 6).then_some(11),
                        driver_version: (version != 6).then_some(12),
                    },
                    formats: claims.media_formats.clone(),
                };
                let permit = verified(&signer, &claims);
                let plain = MediaSessionBinding::from_local_announcement(
                    &permit, &frozen, &local, role, 1_000_000,
                )
                .unwrap();
                let mut binding = SessionBinding {
                    deployment_id: claims.deployment_id.clone(),
                    security_epoch: 1,
                    session_id: claims.session_id.clone(),
                    account_id: claims.account_id.clone(),
                    controller_device_id: claims.controller_device_id.clone(),
                    host_device_id: claims.host_device_id.clone(),
                    controller_key_sha256: controller.fingerprint(),
                    host_key_sha256: host.fingerprint(),
                    resource_id: claims.resource_id.clone(),
                    policy_revision: 1,
                    connection_generation: 9,
                    capability_sha256: [7; 32],
                    granted_permissions: vec![Permission::View],
                    supported_capabilities: claims.required_capabilities.clone(),
                    local_paths: PathSet::DIRECT,
                    media: Some(plain.clone()),
                };
                let now = ClockSample {
                    monotonic_ms: 1000,
                    unix_ms: 1_000_000,
                };
                assert!(
                    Session::activate(permit.clone(), binding.clone(), Path::Direct, 1000, now)
                        .is_err()
                );
                let different = FormatSet::new(vec![format(version, 640)]).unwrap();
                assert!(
                    plain
                        .clone()
                        .with_explicit_media_selection(different, &permit, &local, now.unix_ms)
                        .is_err()
                );
                let mut wrong = local.clone();
                wrong.probe.resource_id = id(99);
                assert!(
                    plain
                        .clone()
                        .with_explicit_media_selection(
                            formats.clone(),
                            &permit,
                            &wrong,
                            now.unix_ms
                        )
                        .is_err()
                );
                wrong = local.clone();
                wrong.probe.backend = "cpu-hardware-readback".into();
                assert!(
                    plain
                        .clone()
                        .with_explicit_media_selection(
                            formats.clone(),
                            &permit,
                            &wrong,
                            now.unix_ms
                        )
                        .is_err()
                );
                wrong = local.clone();
                wrong.expires_at_unix_ms = now.unix_ms;
                assert!(
                    plain
                        .clone()
                        .with_explicit_media_selection(
                            formats.clone(),
                            &permit,
                            &wrong,
                            now.unix_ms
                        )
                        .is_err()
                );
                let selected = plain
                    .with_explicit_media_selection(formats.clone(), &permit, &local, now.unix_ms)
                    .unwrap();
                binding.media = Some(selected.clone());
                let mut session =
                    Session::activate(permit.clone(), binding.clone(), Path::Direct, 1000, now)
                        .unwrap();
                let transcript = session.proof_transcript();
                for (endpoint, identity) in [
                    (EndpointRole::Controller, &controller),
                    (EndpointRole::Host, &host),
                ] {
                    session
                        .confirm_endpoint(
                            endpoint,
                            &identity.public_key(),
                            &identity.prove(&transcript).unwrap(),
                            1001,
                        )
                        .unwrap();
                }
                assert_eq!(session.state(), SessionState::Active);
                let retained = Session::activate_with_retained_deadline(
                    permit,
                    binding.clone(),
                    Path::Direct,
                    ClockSample {
                        monotonic_ms: 1100,
                        unix_ms: 1_000_100,
                    },
                    8000,
                )
                .unwrap();
                assert_eq!(retained.deadline_ms(), 8000);
                for field in 0..7 {
                    let mut changed = claims.clone();
                    match field {
                        0 => changed.account_id = id(90),
                        1 => changed.deployment_id = id(91),
                        2 => changed.controller_device_id = id(92),
                        3 => changed.host_device_id = id(93),
                        4 => changed.session_id = id(94),
                        5 => changed.resource_id = id(95),
                        _ => changed.connection_generation += 1,
                    }
                    assert!(
                        selected
                            .explicit_selection
                            .as_ref()
                            .unwrap()
                            .authorize(&changed)
                            .is_err()
                    );
                }
                claims.lease_sequence += 1;
                claims.issued_at_unix_ms += 1000;
                claims.expires_at_unix_ms += 1000;
                local.revision += 1;
                local.expires_at_unix_ms += 1000;
                session
                    .renew_with_local_media(
                        verified(&signer, &claims),
                        1900,
                        1,
                        &frozen,
                        &local,
                        role,
                        ClockSample {
                            monotonic_ms: 2000,
                            unix_ms: 1_001_000,
                        },
                    )
                    .unwrap();
                assert_eq!(session.permit.claims().lease_sequence, 2);
                assert!(
                    session
                        .binding()
                        .media
                        .as_ref()
                        .unwrap()
                        .explicit_selection
                        .is_some()
                );
                let mut changed_scope = claims.clone();
                let different = FormatSet::new(vec![format(version, 640)]).unwrap();
                changed_scope.media_formats = vec![format(version, 640).encode().unwrap()];
                changed_scope.media_format_sha256 = different.digest().to_vec();
                assert!(
                    selected
                        .explicit_selection
                        .as_ref()
                        .unwrap()
                        .authorize(&changed_scope)
                        .is_err()
                );
                let mut changed_probe = local.clone();
                changed_probe.probe.resource_id = id(98);
                assert!(
                    selected
                        .refresh_from_local_announcement(
                            &verified(&signer, &claims),
                            &frozen,
                            &changed_probe,
                            role,
                            1_001_000
                        )
                        .is_err()
                );
            }
        }
    }
}
