use super::*;
use nestlink_protocol::api::{MediaAnnouncementSubmission, MediaRemoteRequest};
use nestlink_protocol::media_authority::{MediaAnnouncement, MediaDirection, ProbeIdentity};
fn submission(
    s: &mut Store,
    p: &Principal,
    key: &InstallationIdentity,
    id: &str,
    revision: u64,
) -> Result<MediaAnnouncementSubmission> {
    let challenge = s.enrollment_challenge(p, 1000)?;
    let mut body = MediaAnnouncementSubmission {
        challenge_id: challenge.id,
        announcement: MediaAnnouncement {
            version: 2,
            device_id: id.into(),
            direction: MediaDirection::Encode,
            revision,
            expires_at_unix_ms: 1_200_000,
            probe: ProbeIdentity {
                generation: revision,
                resource_id: random_id(),
                backend: "cpu-software".into(),
                adapter_luid: None,
                driver_version: None,
            },
            formats: vec![],
        },
        signature: String::new(),
    };
    body.signature =
        URL_SAFE_NO_PAD.encode(key.sign_action(&s.media_announcement_transcript(p, &body, 1000)?)?);
    Ok(body)
}
#[test]
fn media_announcement_signature_challenge_and_monotonic_withdrawal_are_enforced() -> Result {
    let (mut s, _, _, p, other) = fixture()?;
    let key = InstallationIdentity::generate();
    let id = enroll(&mut s, &p, &key, "media host")?;
    let body = submission(&mut s, &p, &key, &id, 1)?;
    let mut bad = body.clone();
    bad.announcement.revision = 2;
    assert!(s.replace_media_announcement(&p, bad, 1000).is_err());
    assert!(
        s.replace_media_announcement(&other, body.clone(), 1000)
            .is_err()
    );
    s.replace_media_announcement(&p, body.clone(), 1000)?;
    assert!(s.replace_media_announcement(&p, body, 1000).is_err());
    let withdrawn = submission(&mut s, &p, &key, &id, 2)?;
    s.replace_media_announcement(&p, withdrawn, 1000)?;
    let stale = submission(&mut s, &p, &key, &id, 1)?;
    assert!(s.replace_media_announcement(&p, stale, 1000).is_err());
    let current = s
        .media_announcement(&p, &id, MediaDirection::Encode, 1001)?
        .ok_or("missing announcement")?;
    assert_eq!(current.revision, 2);
    assert!(current.formats.is_empty());
    assert!(
        s.media_announcement(&other, &id, MediaDirection::Encode, 1001)
            .is_err()
    );
    assert!(
        s.media_announcement(&p, &id, MediaDirection::Encode, 1200)
            .is_err()
    );
    s.revoke_device_as(&p, &random_id(), &id, 1001)?;
    assert!(
        s.media_announcement(&p, &id, MediaDirection::Encode, 1001)
            .is_err()
    );
    Ok(())
}
#[test]
fn media_authority_request_is_closed_until_real_runtime_and_legacy_stays_unscoped() -> Result {
    let (mut s, _, _, p, _) = fixture()?;
    let c = InstallationIdentity::generate();
    let h = InstallationIdentity::generate();
    let cid = enroll(&mut s, &p, &c, "controller")?;
    let hid = enroll(&mut s, &p, &h, "host")?;
    let request = RemoteRequest {
        id: random_id(),
        controller_device_id: cid,
        host_device_id: hid,
        permissions: vec![Permission::View as i32],
        path_mode: "direct_only".into(),
    };
    assert!(
        s.create_media_remote(
            &p,
            MediaRemoteRequest {
                request: request.clone(),
                media_format_version: 2
            },
            1000
        )
        .is_err()
    );
    let view = s.create_remote(&p, request, 1000)?;
    assert!(s.remote_media_scope(&p, &view.id, 1000)?.is_none());
    Ok(())
}
