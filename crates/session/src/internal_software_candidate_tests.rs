#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use nestlink_identity::{InstallationIdentity, PermitSigner, verify_permit};
use nestlink_protocol::{
    PermitClaims, SCHEMA_VERSION,
    media_authority::{
        FORMAT_CAPABILITY, FrozenMediaScope, MediaAnnouncement, MediaDirection, ProbeIdentity,
    },
    media_format::{FormatSet, FrameRate, VideoFormat},
};
use prost::Message;
fn id(n: u8) -> String {
    format!("{n:08x}-1111-4111-8111-111111111111")
}
fn fixture() -> (
    PermitSigner,
    InstallationIdentity,
    InstallationIdentity,
    PermitClaims,
    SessionBinding,
) {
    let signer = PermitSigner::from_seed([1; 32]);
    let controller = InstallationIdentity::from_seed([2; 32]);
    let host = InstallationIdentity::from_seed([3; 32]);
    let claims = PermitClaims {
        media_format_version: 0,
        media_formats: Vec::new(),
        media_format_sha256: Vec::new(),
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
        permissions: vec![Permission::View as i32, Permission::Input as i32],
        paths: vec![Path::Direct as i32],
        policy_revision: 1,
        connection_generation: 1,
        lease_sequence: 1,
        issued_at_unix_ms: 1_000_000,
        expires_at_unix_ms: 1_015_000,
        capability_sha256: vec![7; 32],
        required_capabilities: vec!["vp8".into()],
    };
    let binding = SessionBinding {
        media: None,
        deployment_id: id(1),
        security_epoch: 1,
        session_id: id(2),
        account_id: id(3),
        controller_device_id: id(4),
        host_device_id: id(5),
        controller_key_sha256: controller.fingerprint(),
        host_key_sha256: host.fingerprint(),
        resource_id: id(6),
        policy_revision: 1,
        connection_generation: 1,
        capability_sha256: [7; 32],
        granted_permissions: vec![Permission::View, Permission::Input],
        supported_capabilities: vec!["vp8".into()],
        local_paths: PathSet::DIRECT,
    };
    (signer, controller, host, claims, binding)
}

fn verified(signer: &PermitSigner, claims: &PermitClaims) -> nestlink_identity::VerifiedPermit {
    verify_permit(
        &signer.sign(claims).unwrap().encode_to_vec(),
        &signer.public_key(),
    )
    .unwrap()
}

// These synthetic permit/evidence records test authorization only, not a local probe.
fn candidate(
    role: EndpointRole,
) -> (
    Session,
    PermitSigner,
    PermitClaims,
    FrozenMediaScope,
    MediaAnnouncement,
) {
    let (signer, controller, host, mut claims, mut binding) = fixture();
    let format =
        VideoFormat::legacy_h264(31, 320, 240, FrameRate::new(30, 1).unwrap(), 2000).unwrap();
    claims.media_format_version = 2;
    claims.media_formats = vec![format.encode().unwrap()];
    claims.media_format_sha256 = FormatSet::new(vec![format]).unwrap().digest().to_vec();
    claims.required_capabilities = vec![
        FORMAT_CAPABILITY.into(),
        nestlink_protocol::media::H264_CAPABILITY.into(),
    ];
    let frozen = FrozenMediaScope {
        version: 2,
        controller_revision: 1,
        host_revision: 1,
        formats: claims.media_formats.clone(),
        sha256: claims.media_format_sha256.clone(),
    };
    let local = MediaAnnouncement {
        version: 2,
        device_id: if role == EndpointRole::Host {
            claims.host_device_id.clone()
        } else {
            claims.controller_device_id.clone()
        },
        direction: if role == EndpointRole::Host {
            MediaDirection::Encode
        } else {
            MediaDirection::Decode
        },
        revision: 1,
        expires_at_unix_ms: 1_030_000,
        probe: ProbeIdentity {
            generation: 1,
            resource_id: id(8),
            backend: "cpu-software".into(),
            adapter_luid: None,
            driver_version: None,
        },
        formats: claims.media_formats.clone(),
    };
    let policy =
        nestlink_protocol::internal_software_media_candidate::InternalSoftwareMediaCandidate {
            deployment_id: claims.deployment_id.clone(),
            account_id: claims.account_id.clone(),
            controller_device_id: claims.controller_device_id.clone(),
            host_device_id: claims.host_device_id.clone(),
            format: format.encode().unwrap(),
            format_sha256: format.digest().unwrap(),
            additional_formats: Vec::new(),
        };
    let permit = verified(&signer, &claims);
    let local_binding =
        MediaSessionBinding::from_local_announcement(&permit, &frozen, &local, role, 1_000_000)
            .unwrap();
    binding.supported_capabilities = claims.required_capabilities.clone();
    binding.media = Some(local_binding.clone());
    let now = ClockSample {
        monotonic_ms: 1000,
        unix_ms: 1_000_000,
    };
    assert!(Session::activate(permit.clone(), binding.clone(), Path::Direct, 1000, now).is_err());
    for wrong in 0..5 {
        let mut changed = policy.clone();
        match wrong {
            0 => changed.account_id = id(20),
            1 => changed.controller_device_id = id(21),
            2 => changed.host_device_id = id(22),
            3 => changed.deployment_id = id(23),
            _ => {
                let other =
                    VideoFormat::legacy_h264(31, 640, 480, FrameRate::new(30, 1).unwrap(), 2000)
                        .unwrap();
                changed.format = other.encode().unwrap();
                changed.format_sha256 = other.digest().unwrap();
            }
        }
        assert!(
            local_binding
                .clone()
                .with_internal_software_candidate(changed, &permit, &local, 1_000_000)
                .is_err()
        );
    }
    let mut expired = local.clone();
    expired.expires_at_unix_ms = 999_999;
    assert!(
        local_binding
            .clone()
            .with_internal_software_candidate(policy.clone(), &permit, &expired, 1_000_000)
            .is_err()
    );
    let mut gpu = local.clone();
    gpu.probe.backend = "gpu-presenter".into();
    gpu.probe.adapter_luid = Some(1);
    gpu.probe.driver_version = Some(1);
    assert!(
        local_binding
            .clone()
            .with_internal_software_candidate(policy.clone(), &permit, &gpu, 1_000_000)
            .is_err()
    );
    binding.media = Some(
        local_binding
            .with_internal_software_candidate(policy, &permit, &local, 1_000_000)
            .unwrap(),
    );
    let mut session =
        Session::activate(permit.clone(), binding.clone(), Path::Direct, 1000, now).unwrap();
    assert_eq!(session.state(), SessionState::AwaitingProof);
    let transcript = session.proof_transcript();
    for (endpoint, identity) in [
        (EndpointRole::Controller, controller),
        (EndpointRole::Host, host),
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
        binding,
        Path::Direct,
        ClockSample {
            monotonic_ms: 1100,
            unix_ms: 1_000_100,
        },
        8000,
    )
    .unwrap();
    assert_eq!(retained.state(), SessionState::AwaitingProof);
    assert_eq!(retained.deadline_ms(), 8000);
    (session, signer, claims, frozen, local)
}
#[test]
fn internal_software_candidate_normal_activation_proofs_renewal_and_retained_deadline() {
    for role in [EndpointRole::Host, EndpointRole::Controller] {
        let (mut session, signer, mut claims, frozen, mut local) = candidate(role);
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
        assert_eq!(session.current_verified_permit().claims().lease_sequence, 2);
        assert!(
            session
                .binding()
                .media
                .as_ref()
                .unwrap()
                .internal_candidate
                .is_some()
        );
        // Current binding validation, used by path selection and all renewal checks,
        // retains the original exact policy instead of importing a new target.
        let mut changed = claims.clone();
        changed.account_id = id(24);
        assert!(
            session
                .validate_current_binding(&verified(&signer, &changed), Path::Direct)
                .is_err()
        );
        let mut changed = claims.clone();
        changed.host_device_id = id(25);
        assert!(
            session
                .validate_current_binding(&verified(&signer, &changed), Path::Direct)
                .is_err()
        );
    }
}

#[test]
fn internal_software_candidate_wrong_account_or_target_successor_stops_without_publishing() {
    for wrong_target in [false, true] {
        let (mut session, signer, mut claims, mut frozen, mut local) =
            candidate(EndpointRole::Host);
        let before = session.binding().media.clone();
        claims.lease_sequence = 2;
        claims.issued_at_unix_ms += 1000;
        claims.expires_at_unix_ms += 1000;
        local.revision += 1;
        local.expires_at_unix_ms += 1000;
        if wrong_target {
            let other =
                VideoFormat::legacy_h264(31, 640, 480, FrameRate::new(30, 1).unwrap(), 2000)
                    .unwrap();
            claims.media_formats = vec![other.encode().unwrap()];
            claims.media_format_sha256 = FormatSet::new(vec![other]).unwrap().digest().to_vec();
            frozen.formats = claims.media_formats.clone();
            frozen.sha256 = claims.media_format_sha256.clone();
            local.formats = claims.media_formats.clone();
        } else {
            claims.account_id = id(29);
        }
        assert!(
            session
                .renew_with_local_media(
                    verified(&signer, &claims),
                    1900,
                    1,
                    &frozen,
                    &local,
                    EndpointRole::Host,
                    ClockSample {
                        monotonic_ms: 2000,
                        unix_ms: 1_001_000
                    }
                )
                .is_err()
        );
        assert_eq!(session.current_verified_permit().claims().lease_sequence, 1);
        assert_eq!(session.binding().media, before);
        assert_eq!(
            session.state(),
            SessionState::Stopped(StopReason::PlatformChanged)
        );
    }
}
