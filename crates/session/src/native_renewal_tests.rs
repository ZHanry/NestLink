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

fn media() -> (
    Session,
    PermitSigner,
    PermitClaims,
    FrozenMediaScope,
    MediaAnnouncement,
) {
    let (signer, controller, host, mut claims, mut binding) = fixture();
    let format =
        VideoFormat::legacy_h264(31, 320, 240, FrameRate::new(30, 1).unwrap(), 2000).unwrap();
    let formats = FormatSet::new(vec![format]).unwrap();
    claims.media_format_version = 2;
    claims.media_formats = vec![format.encode().unwrap()];
    claims.media_format_sha256 = formats.digest().to_vec();
    claims.required_capabilities = vec![FORMAT_CAPABILITY.into()];
    let frozen = FrozenMediaScope {
        version: 2,
        controller_revision: 1,
        host_revision: 2,
        formats: claims.media_formats.clone(),
        sha256: claims.media_format_sha256.clone(),
    };
    let local = MediaAnnouncement {
        version: 2,
        device_id: claims.host_device_id.clone(),
        direction: MediaDirection::Encode,
        revision: 2,
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
    claims.session_id = MEDIA_REGRESSION_SESSION_ID.into();
    binding.session_id = MEDIA_REGRESSION_SESSION_ID.into();
    let permit = verified(&signer, &claims);
    binding.media = Some(
        MediaSessionBinding::from_local_announcement(
            &permit,
            &frozen,
            &local,
            EndpointRole::Host,
            1_000_000,
        )
        .unwrap(),
    );
    binding.supported_capabilities = claims.required_capabilities.clone();
    // Module-private regression admission; no public or production bypass.
    let mut session = Session::activate_with_rollout(
        permit,
        binding,
        Path::Direct,
        1000,
        ClockSample {
            monotonic_ms: 1000,
            unix_ms: 1_000_000,
        },
        true,
    )
    .unwrap();
    let transcript = session.proof_transcript();
    for (role, identity) in [
        (EndpointRole::Controller, controller),
        (EndpointRole::Host, host),
    ] {
        session
            .confirm_endpoint(
                role,
                &identity.public_key(),
                &identity.prove(&transcript).unwrap(),
                1001,
            )
            .unwrap();
    }
    (session, signer, claims, frozen, local)
}
#[test]
fn atomic_media_renewal_publishes_binding_and_exact_successor_together() {
    let (mut session, signer, mut claims, frozen, mut local) = media();
    claims.lease_sequence = 2;
    claims.issued_at_unix_ms = 1_001_000;
    claims.expires_at_unix_ms = 1_016_000;
    local.revision = 3;
    local.expires_at_unix_ms = 1_040_000;
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
                unix_ms: 1_001_000,
            },
        )
        .unwrap();
    assert_eq!(session.current_verified_permit().claims().lease_sequence, 2);
    assert_eq!(
        session
            .binding()
            .media
            .as_ref()
            .unwrap()
            .expires_at_unix_ms(),
        1_040_000
    );
    assert_eq!(session.deadline_ms(), 16900);
}
#[test]
fn failed_successor_does_not_publish_prepared_binding() {
    let (mut session, signer, mut claims, frozen, mut local) = media();
    let original = session.binding().media.clone();
    claims.lease_sequence = 2;
    claims.permissions = vec![Permission::View as i32];
    local.revision = 3;
    local.expires_at_unix_ms = 1_040_000;
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
    assert_eq!(session.binding().media, original);
    assert!(matches!(session.state(), SessionState::Stopped(_)));
}
#[test]
fn expired_or_stopped_local_lease_never_revives_from_signed_successor() {
    for reason in [Some(StopReason::Revoked), None] {
        let (mut session, signer, mut claims, frozen, local) = media();
        claims.lease_sequence = 2;
        claims.issued_at_unix_ms = 1_015_000;
        claims.expires_at_unix_ms = 1_030_000;
        if let Some(reason) = reason {
            session.stop(reason);
        }
        assert!(
            session
                .renew_with_local_media(
                    verified(&signer, &claims),
                    15999,
                    1,
                    &frozen,
                    &local,
                    EndpointRole::Host,
                    ClockSample {
                        monotonic_ms: 16000,
                        unix_ms: 1_015_000
                    }
                )
                .is_err()
        );
        assert_eq!(session.current_verified_permit().claims().lease_sequence, 1);
        assert!(matches!(session.state(), SessionState::Stopped(_)));
    }
}
