//! Synthetic signed-data regressions only; never local hardware qualification.
use super::*;
use nestlink_auth::{VaultKey, hash_password};
use nestlink_identity::InstallationIdentity;
use nestlink_protocol::api::{
    MediaAnnouncementSubmission, MediaApprovalChoice, MediaApprovalSubmission,
};
use nestlink_protocol::media_authority::{MediaAnnouncement, MediaDirection, ProbeIdentity};
use nestlink_protocol::media_format::{FrameRate, VideoFormat};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn enroll(s: &mut Store, p: &Principal, key: &InstallationIdentity) -> TestResult<String> {
    let challenge = s.enrollment_challenge(p, 1000)?;
    let id = random_id();
    let mut body = DeviceRegistration {
        challenge_id: challenge.id,
        device: DeviceDescriptor {
            id: id.clone(),
            name: "test fixture".into(),
            platform: "windows".into(),
            public_key: URL_SAFE_NO_PAD.encode(key.public_key()),
            capabilities: vec!["controller".into(), "host".into(), "vp8".into()],
            path_mode: "direct_only".into(),
        },
        signature: String::new(),
    };
    body.signature =
        URL_SAFE_NO_PAD.encode(key.sign_action(&s.registration_transcript(p, &body, 1000)?)?);
    s.register_device(p, body, 1000)?;
    Ok(id)
}
fn publish(
    s: &mut Store,
    p: &Principal,
    key: &InstallationIdentity,
    id: &str,
    direction: MediaDirection,
    revision: u64,
    formats: Vec<Vec<u8>>,
) -> TestResult {
    let challenge = s.enrollment_challenge(p, 1000)?;
    let mut body = MediaAnnouncementSubmission {
        challenge_id: challenge.id,
        announcement: MediaAnnouncement {
            version: 2,
            device_id: id.into(),
            direction,
            revision,
            expires_at_unix_ms: 1_200_000,
            probe: ProbeIdentity {
                generation: revision,
                resource_id: random_id(),
                backend: "cpu-software".into(),
                adapter_luid: None,
                driver_version: None,
            },
            formats,
        },
        signature: String::new(),
    };
    body.signature =
        URL_SAFE_NO_PAD.encode(key.sign_action(&s.media_announcement_transcript(p, &body, 1000)?)?);
    s.replace_media_announcement(p, body, 1000)?;
    Ok(())
}
#[test]
fn frozen_scope_requires_explicit_signed_approval_and_never_widens_from_latest_catalog()
-> TestResult {
    let mut s = Store::in_memory(&random_id())?;
    let vault = VaultKey::from_bytes([7; 32]);
    let password = "integration-only-password";
    s.bootstrap_admin("Admin", password)?;
    let dummy = hash_password(password)?;
    let p = s
        .login("admin", password, None, 1000, &vault, &dummy)?
        .principal;
    let c = InstallationIdentity::generate();
    let h = InstallationIdentity::generate();
    let cid = enroll(&mut s, &p, &c)?;
    let hid = enroll(&mut s, &p, &h)?;
    let f = VideoFormat::legacy_h264(31, 320, 240, FrameRate::new(30, 1)?, 2000)?;
    publish(
        &mut s,
        &p,
        &c,
        &cid,
        MediaDirection::Decode,
        1,
        vec![f.encode()?],
    )?;
    publish(
        &mut s,
        &p,
        &h,
        &hid,
        MediaDirection::Encode,
        1,
        vec![f.encode()?],
    )?;
    let request = RemoteRequest {
        id: random_id(),
        controller_device_id: cid.clone(),
        host_device_id: hid.clone(),
        permissions: vec![Permission::View as i32],
        path_mode: "direct_only".into(),
    };
    // Exercise dormant transaction logic directly inside its private module;
    // public creation and all production signing remain hard disabled.
    let view = s.create_remote_kind(&p, request.clone(), 1000, false, true)?;
    let scope = s
        .remote_media_scope(&p, &view.id, 1000)?
        .ok_or("missing scope")?;
    assert_eq!(scope.formats, vec![f.encode()?]);
    assert!(s.create_remote(&p, request, 1000).is_err());
    let legacy = ApprovalChoice {
        approved: true,
        permissions: vec![Permission::View as i32],
        paths: vec![1],
    };
    assert!(s.approval_transcript(&p, &view.id, &legacy, 1000).is_err());
    let mut choice = MediaApprovalChoice {
        choice: legacy,
        media_format_sha256: scope.sha256.clone(),
    };
    choice.media_format_sha256[0] ^= 1;
    assert!(
        s.media_approval_transcript(&p, &view.id, &choice, 1000)
            .is_err()
    );
    choice.media_format_sha256 = scope.sha256.clone();
    let proof = s.media_approval_transcript(&p, &view.id, &choice, 1000)?;
    let body = MediaApprovalSubmission {
        choice,
        signature: URL_SAFE_NO_PAD.encode(h.sign_action(&proof)?),
    };
    s.approve_media_remote(&p, &view.id, body, 1000)?;
    assert!(s.initial_permit(&p, &view.id, 1000).is_err());
    let other = VideoFormat::legacy_h264(31, 640, 480, FrameRate::new(30, 1)?, 2000)?;
    let set = nestlink_protocol::media_format::FormatSet::new(vec![f, other])?;
    let expanded = set
        .formats()
        .iter()
        .map(|f| f.encode())
        .collect::<Result<Vec<_>, _>>()?;
    publish(
        &mut s,
        &p,
        &c,
        &cid,
        MediaDirection::Decode,
        2,
        expanded.clone(),
    )?;
    publish(&mut s, &p, &h, &hid, MediaDirection::Encode, 2, expanded)?;
    assert_eq!(
        s.remote_media_scope(&p, &view.id, 1000)?
            .ok_or("missing scope")?,
        scope
    );
    s.require_media_still_available(&view.id, &scope, 1000)?;
    publish(&mut s, &p, &h, &hid, MediaDirection::Encode, 3, vec![])?;
    assert!(
        s.require_media_still_available(&view.id, &scope, 1000)
            .is_err()
    );
    assert_eq!(
        s.remote_media_scope(&p, &view.id, 1000)?
            .ok_or("missing scope")?,
        scope
    );
    Ok(())
}

// These exercises run only when explicitly admitted per request on an owned
// in-memory Store. They use the real public control methods and signed proofs.
struct MediaLifecycle {
    store: Store,
    principal: Principal,
    controller: InstallationIdentity,
    host: InstallationIdentity,
    controller_id: String,
    host_id: String,
    request_id: String,
    format: VideoFormat,
    scope: nestlink_protocol::media_authority::FrozenMediaScope,
}
impl MediaLifecycle {
    fn new(expires_at_unix_ms: u64) -> TestResult<Self> {
        Self::new_with_candidate(expires_at_unix_ms, false)
    }
    fn new_with_candidate(expires_at_unix_ms: u64, candidate: bool) -> TestResult<Self> {
        let mut store = Store::in_memory(&random_id())?;
        let vault = VaultKey::from_bytes([17; 32]);
        let password = "media-lifecycle-test-only-password";
        store.bootstrap_admin("Admin", password)?;
        let principal = store
            .login(
                "admin",
                password,
                None,
                1000,
                &vault,
                &hash_password(password)?,
            )?
            .principal;
        let controller = InstallationIdentity::generate();
        let host = InstallationIdentity::generate();
        let controller_id = enroll(&mut store, &principal, &controller)?;
        let host_id = enroll(&mut store, &principal, &host)?;
        let format = VideoFormat::legacy_h264(31, 320, 240, FrameRate::new(30, 1)?, 2000)?;
        let request_id = random_id();
        let scope = nestlink_protocol::media_authority::FrozenMediaScope {
            version: 2,
            controller_revision: 1,
            host_revision: 1,
            formats: vec![format.encode()?],
            sha256: nestlink_protocol::media_format::FormatSet::new(vec![format])?
                .digest()
                .to_vec(),
        };
        let mut fixture = Self {
            store,
            principal,
            controller,
            host,
            controller_id,
            host_id,
            request_id,
            format,
            scope,
        };
        fixture.announce(
            MediaDirection::Decode,
            1,
            expires_at_unix_ms,
            vec![format.encode()?],
        )?;
        fixture.announce(
            MediaDirection::Encode,
            1,
            expires_at_unix_ms,
            vec![format.encode()?],
        )?;
        let request = nestlink_protocol::api::MediaRemoteRequest {
            media_format_version: 2,
            request: RemoteRequest {
                id: fixture.request_id.clone(),
                controller_device_id: fixture.controller_id.clone(),
                host_device_id: fixture.host_id.clone(),
                permissions: vec![Permission::View as i32],
                path_mode: "direct_only".into(),
            },
        };
        // Test compilation alone does not enable the gate, even with valid
        // signed catalogs. Admission is scoped to this Store and this UUID.
        assert!(
            fixture
                .store
                .create_media_remote(&fixture.principal, request.clone(), 1000)
                .is_err()
        );
        if candidate {
            let policy = nestlink_protocol::internal_software_media_candidate::InternalSoftwareMediaCandidate {
                deployment_id: fixture.store.deployment_id()?,
                account_id: fixture.principal.account_id.clone(),
                controller_device_id: fixture.controller_id.clone(),
                host_device_id: fixture.host_id.clone(),
                format: fixture.format.encode()?,
                format_sha256: fixture.format.digest()?,
            };
            fixture.store = fixture
                .store
                .with_internal_software_media_candidate(policy)?;
            assert!(fixture.store.media_regression_requests.is_empty());
        } else {
            fixture
                .store
                .admit_media_regression_request(&fixture.request_id)?;
        }
        let mut other = request.clone();
        other.request.id = random_id();
        if candidate {
            other.request.host_device_id = random_id();
        }
        assert!(
            fixture
                .store
                .create_media_remote(&fixture.principal, other, 1000)
                .is_err()
        );
        let isolated = Store::in_memory(&random_id())?;
        assert!(!isolated.media_issuance_enabled_for_request(&fixture.request_id));
        let view = fixture
            .store
            .create_media_remote(&fixture.principal, request, 1000)?;
        fixture.scope = fixture
            .store
            .remote_media_scope(&fixture.principal, &view.id, 1000)?
            .ok_or("missing frozen scope")?;
        assert_eq!(fixture.scope.formats, vec![fixture.format.encode()?]);
        Ok(fixture)
    }
    fn announce(
        &mut self,
        direction: MediaDirection,
        revision: u64,
        expiry: u64,
        formats: Vec<Vec<u8>>,
    ) -> TestResult {
        self.announce_at(direction, revision, expiry, formats, 1000)
    }
    fn announce_at(
        &mut self,
        direction: MediaDirection,
        revision: u64,
        expiry: u64,
        formats: Vec<Vec<u8>>,
        now: u64,
    ) -> TestResult {
        let (key, id) = match direction {
            MediaDirection::Decode => (&self.controller, &self.controller_id),
            MediaDirection::Encode => (&self.host, &self.host_id),
        };
        let challenge = self.store.enrollment_challenge(&self.principal, now)?;
        let mut body = MediaAnnouncementSubmission {
            challenge_id: challenge.id,
            announcement: MediaAnnouncement {
                version: 2,
                device_id: id.clone(),
                direction,
                revision,
                expires_at_unix_ms: expiry,
                probe: ProbeIdentity {
                    generation: revision,
                    resource_id: random_id(),
                    backend: "cpu-software".into(),
                    adapter_luid: None,
                    driver_version: None,
                },
                formats,
            },
            signature: String::new(),
        };
        body.signature =
            URL_SAFE_NO_PAD.encode(key.sign_action(&self.store.media_announcement_transcript(
                &self.principal,
                &body,
                now,
            )?)?);
        self.store
            .replace_media_announcement(&self.principal, body, now)?;
        Ok(())
    }
    fn approve(&mut self, approved: bool, now: u64) -> TestResult {
        let choice = MediaApprovalChoice {
            choice: ApprovalChoice {
                approved,
                permissions: if approved { vec![1] } else { vec![] },
                paths: if approved { vec![1] } else { vec![] },
            },
            media_format_sha256: self.scope.sha256.clone(),
        };
        let proof = self.store.media_approval_transcript(
            &self.principal,
            &self.request_id,
            &choice,
            now,
        )?;
        self.store.approve_media_remote(
            &self.principal,
            &self.request_id,
            MediaApprovalSubmission {
                signature: URL_SAFE_NO_PAD.encode(self.host.sign_action(&proof)?),
                choice,
            },
            now,
        )?;
        Ok(())
    }
    fn renewal(&self, sequence: u64, now: u64) -> TestResult<RenewalSubmission> {
        let controller = self.store.renewal_transcript(
            &self.principal,
            &self.request_id,
            sequence,
            false,
            now,
        )?;
        let host = self.store.renewal_transcript(
            &self.principal,
            &self.request_id,
            sequence,
            true,
            now,
        )?;
        Ok(RenewalSubmission {
            lease_sequence: sequence,
            controller_signature: URL_SAFE_NO_PAD.encode(self.controller.sign_action(&controller)?),
            host_signature: URL_SAFE_NO_PAD.encode(self.host.sign_action(&host)?),
        })
    }
    fn reconnection(
        &self,
        permit: &nestlink_protocol::PermitClaims,
    ) -> TestResult<nestlink_protocol::api::ReconnectionSubmission> {
        use nestlink_identity::reconnection::transcript;
        use prost::Message;
        let choice = nestlink_protocol::api::ReconnectionChoice {
            previous_permit_sha256: URL_SAFE_NO_PAD.encode(digest(&permit.encode_to_vec())),
            connection_generation: permit.connection_generation + 1,
            lease_sequence: permit.lease_sequence + 1,
            nonce: URL_SAFE_NO_PAD.encode([19; 32]),
        };
        Ok(nestlink_protocol::api::ReconnectionSubmission {
            controller_signature: URL_SAFE_NO_PAD.encode(
                self.controller
                    .sign_action(&transcript(permit, &self.controller_id, &choice)?)?,
            ),
            host_signature: URL_SAFE_NO_PAD.encode(self.host.sign_action(&transcript(
                permit,
                &self.host_id,
                &choice,
            )?)?),
            choice,
        })
    }
    fn assert_scope(&self, permit: &nestlink_protocol::PermitClaims) -> TestResult {
        assert_eq!(permit.media_format_version, self.scope.version);
        assert_eq!(permit.media_formats, self.scope.formats);
        assert_eq!(permit.media_format_sha256, self.scope.sha256);
        assert!(nestlink_protocol::media_authority::permit_formats(permit)?.is_some());
        Ok(())
    }
}

#[test]
fn signed_media_public_lifecycle_issues_renews_and_reconnects_without_scope_widening() -> TestResult
{
    use prost::Message;
    let mut f = MediaLifecycle::new(1_200_000)?;
    f.approve(true, 1001)?;
    let initial = f.store.initial_permit(&f.principal, &f.request_id, 1001)?;
    f.assert_scope(&initial)?;
    assert_eq!(initial.lease_sequence, 1);
    // Exercise the same final claims-signing/verification boundary as server
    // responses, using an isolated fixture issuer, not deployment credentials.
    let issuer = nestlink_identity::PermitSigner::from_seed([23; 32]);
    let verified = nestlink_identity::verify_permit(
        &issuer.sign(&initial)?.encode_to_vec(),
        &issuer.public_key(),
    )?;
    assert_eq!(verified.claims(), &initial);
    let other = VideoFormat::legacy_h264(31, 640, 480, FrameRate::new(30, 1)?, 2000)?;
    let expanded = nestlink_protocol::media_format::FormatSet::new(vec![f.format, other])?
        .formats()
        .iter()
        .map(|format| format.encode())
        .collect::<Result<Vec<_>, _>>()?;
    f.announce(MediaDirection::Decode, 2, 1_200_000, expanded.clone())?;
    f.announce(MediaDirection::Encode, 2, 1_200_000, expanded)?;
    let renewal = f.renewal(2, 1002)?;
    let renewed = f
        .store
        .renew_permit(&f.principal, &f.request_id, renewal, 1002)?;
    f.assert_scope(&renewed)?;
    assert_eq!(renewed.lease_sequence, 2);
    assert_eq!(
        nestlink_identity::verify_permit(
            &issuer.sign(&renewed)?.encode_to_vec(),
            &issuer.public_key()
        )?
        .claims(),
        &renewed
    );
    let submission = f.reconnection(&renewed)?;
    let receipt =
        f.store
            .reconnect_permit(&f.principal, &f.request_id, submission.clone(), 1003)?;
    nestlink_identity::reconnection::validate_successor(
        &renewed,
        &receipt.next,
        &submission.choice,
    )?;
    f.assert_scope(&receipt.next)?;
    let signed_grant =
        issuer.sign_reconnection(&receipt.previous, &receipt.submission, &receipt.next)?;
    assert_eq!(
        nestlink_identity::reconnection::verify_reconnection(
            &signed_grant.encode_to_vec(),
            &issuer.public_key(),
            &renewed,
            &submission
        )?
        .claims(),
        &receipt.next
    );
    assert_eq!(receipt.next.connection_generation, 2);
    assert_eq!(receipt.next.lease_sequence, 3);
    assert_eq!(
        f.store
            .reconnect_permit(&f.principal, &f.request_id, submission, 1004)?
            .next,
        receipt.next
    );
    assert_eq!(
        f.store.current_permit(&f.principal, &f.request_id, 1004)?,
        receipt.next
    );
    assert_eq!(
        f.store
            .remote_media_scope(&f.principal, &f.request_id, 1004)?
            .ok_or("missing frozen scope")?,
        f.scope
    );
    // Revoking only test admission restores the real production gate for all
    // cached/current paths; it cannot leave a usable cached v2 permit behind.
    f.store.media_regression_requests.clear();
    assert!(
        f.store
            .current_permit(&f.principal, &f.request_id, 1004)
            .is_err()
    );
    assert!(
        f.store
            .initial_permit(&f.principal, &f.request_id, 1004)
            .is_err()
    );
    Ok(())
}

#[test]
fn expired_or_withdrawn_announcements_allow_reviewed_decision_but_block_initial_issuance()
-> TestResult {
    for withdrawn in [false, true] {
        let mut f = MediaLifecycle::new(1_002_000)?;
        if withdrawn {
            f.announce(MediaDirection::Encode, 2, 1_200_000, vec![])?;
        }
        // Approval authenticates the immutable human decision. Availability is
        // enforced when issuing, so an expired catalog cannot produce a lease.
        f.approve(true, 1003)?;
        assert_eq!(
            f.store.remote(&f.principal, &f.request_id)?.status,
            "approved"
        );
        assert!(
            f.store
                .initial_permit(&f.principal, &f.request_id, 1003)
                .is_err()
        );
        assert!(
            f.store
                .current_permit(&f.principal, &f.request_id, 1003)
                .is_err()
        );
    }
    // Rejection remains possible after withdrawal and cannot create a session.
    let mut f = MediaLifecycle::new(1_200_000)?;
    f.announce(MediaDirection::Encode, 2, 1_200_000, vec![])?;
    f.approve(false, 1001)?;
    assert_eq!(
        f.store.remote(&f.principal, &f.request_id)?.status,
        "rejected"
    );
    assert!(
        f.store
            .initial_permit(&f.principal, &f.request_id, 1001)
            .is_err()
    );
    Ok(())
}

#[test]
fn expired_or_withdrawn_announcements_block_prepared_renewal_and_reconnection() -> TestResult {
    for withdrawn in [false, true] {
        let mut f = MediaLifecycle::new(1_004_000)?;
        f.approve(true, 1001)?;
        let initial = f.store.initial_permit(&f.principal, &f.request_id, 1001)?;
        let renewal = f.renewal(2, 1002)?;
        let reconnection = f.reconnection(&initial)?;
        if withdrawn {
            f.announce(MediaDirection::Encode, 2, 1_200_000, vec![])?;
        }
        let now = if withdrawn { 1003 } else { 1005 };
        assert!(
            f.store
                .renew_permit(&f.principal, &f.request_id, renewal, now)
                .is_err()
        );
        assert!(
            f.store
                .reconnect_permit(&f.principal, &f.request_id, reconnection, now)
                .is_err()
        );
        assert!(
            f.store
                .renewal_transcript(&f.principal, &f.request_id, 2, false, now)
                .is_err()
        );
        assert_eq!(
            f.store.remote(&f.principal, &f.request_id)?.lease_sequence,
            1
        );
        assert_eq!(
            f.store
                .remote(&f.principal, &f.request_id)?
                .connection_generation,
            1
        );
    }
    Ok(())
}

#[test]
fn management_expiry_only_absence_does_not_hide_tampering_and_fresh_signed_publication_recovers()
-> TestResult {
    let mut f = MediaLifecycle::new(1_004_000)?;
    assert!(
        f.store
            .media_announcement(&f.principal, &f.host_id, MediaDirection::Encode, 1001)?
            .is_some()
    );
    assert!(
        f.store
            .media_announcement(&f.principal, &f.host_id, MediaDirection::Encode, 1005)?
            .is_none()
    );
    assert!(
        f.store
            .current_media_announcement(&f.host_id, MediaDirection::Encode, 1005)
            .is_err()
    );
    assert!(
        f.store
            .require_media_still_available(&f.request_id, &f.scope, 1005)
            .is_err()
    );
    let mut other = f.principal.clone();
    other.account_id = random_id();
    assert!(
        f.store
            .media_announcement(&other, &f.host_id, MediaDirection::Encode, 1005)
            .is_err()
    );
    let signature:Vec<u8>=f.store.connection.query_row("SELECT signature FROM device_media_announcements WHERE device_id=?1 AND direction='encode'",[&f.host_id],|row|row.get(0))?;
    f.store.connection.execute("UPDATE device_media_announcements SET signature=zeroblob(64) WHERE device_id=?1 AND direction='encode'",[&f.host_id])?;
    assert!(
        f.store
            .media_announcement(&f.principal, &f.host_id, MediaDirection::Encode, 1005)
            .is_err()
    );
    f.store.connection.execute("UPDATE device_media_announcements SET signature=?2 WHERE device_id=?1 AND direction='encode'",rusqlite::params![f.host_id,signature])?;
    assert!(
        f.store
            .media_announcement(&f.principal, &f.host_id, MediaDirection::Encode, 1005)?
            .is_none()
    );
    // A real client must obtain fresh actual probe evidence before constructing
    // these new signed observations. This fixture proves the storage path only.
    f.announce_at(
        MediaDirection::Decode,
        2,
        1_200_000,
        vec![f.format.encode()?],
        1005,
    )?;
    f.announce_at(
        MediaDirection::Encode,
        2,
        1_200_000,
        vec![f.format.encode()?],
        1005,
    )?;
    let fresh = f
        .store
        .media_announcement(&f.principal, &f.host_id, MediaDirection::Encode, 1005)?
        .ok_or("missing fresh announcement")?;
    assert_eq!(fresh.revision, 2);
    assert_eq!(fresh.probe.generation, 2);
    f.store
        .require_media_still_available(&f.request_id, &f.scope, 1005)?;
    f.approve(true, 1005)?;
    let permit = f.store.initial_permit(&f.principal, &f.request_id, 1005)?;
    f.assert_scope(&permit)?;
    assert_eq!(
        f.store
            .remote_media_scope(&f.principal, &f.request_id, 1005)?
            .ok_or("missing frozen scope")?,
        f.scope
    );
    Ok(())
}

#[test]
fn internal_software_candidate_uses_public_first_approval_issuance_renewal_and_recovery()
-> TestResult {
    // Synthetic signed records exercise authorization; this is not hardware evidence.
    let mut f = MediaLifecycle::new_with_candidate(1_200_000, true)?;
    assert!(f.store.media_regression_requests.is_empty());
    assert!(
        f.store
            .initial_permit(&f.principal, &f.request_id, 1000)
            .is_err()
    );
    let legacy = ApprovalChoice {
        approved: true,
        permissions: vec![1],
        paths: vec![1],
    };
    assert!(
        f.store
            .approval_transcript(&f.principal, &f.request_id, &legacy, 1000)
            .is_err()
    );
    f.approve(true, 1001)?;
    let initial = f.store.initial_permit(&f.principal, &f.request_id, 1001)?;
    f.assert_scope(&initial)?;
    let renewal = f.renewal(2, 1002)?;
    let renewed = f
        .store
        .renew_permit(&f.principal, &f.request_id, renewal, 1002)?;
    f.assert_scope(&renewed)?;
    let reconnect = f.reconnection(&renewed)?;
    let receipt = f
        .store
        .reconnect_permit(&f.principal, &f.request_id, reconnect, 1003)?;
    f.assert_scope(&receipt.next)?;
    assert_eq!(receipt.next.connection_generation, 2);
    assert!(f.store.media_regression_requests.is_empty());
    let other = VideoFormat::legacy_h264(31, 640, 480, FrameRate::new(30, 1)?, 2000)?;
    let expanded = nestlink_protocol::media_format::FormatSet::new(vec![f.format, other])?
        .formats()
        .iter()
        .map(|f| f.encode())
        .collect::<Result<Vec<_>, _>>()?;
    f.announce(MediaDirection::Decode, 2, 1_200_000, expanded.clone())?;
    f.announce(MediaDirection::Encode, 2, 1_200_000, expanded)?;
    assert!(
        f.store
            .current_permit(&f.principal, &f.request_id, 1003)
            .is_err()
    );
    assert_eq!(
        f.store
            .remote_media_scope(&f.principal, &f.request_id, 1003)?
            .ok_or("scope missing")?,
        f.scope
    );
    Ok(())
}

#[test]
fn internal_software_candidate_rejects_account_peer_target_and_expiry() -> TestResult {
    let mut f = MediaLifecycle::new_with_candidate(1_200_000, true)?;
    let policy = f
        .store
        .internal_software_media_candidate
        .clone()
        .ok_or("policy missing")?;
    for wrong in 0..4 {
        let mut changed = policy.clone();
        match wrong {
            0 => changed.account_id = random_id(),
            1 => changed.controller_device_id = random_id(),
            2 => changed.host_device_id = random_id(),
            _ => {
                let other = VideoFormat::legacy_h264(31, 640, 480, FrameRate::new(30, 1)?, 2000)?;
                changed.format = other.encode()?;
                changed.format_sha256 = other.digest()?;
            }
        }
        f.store.internal_software_media_candidate = Some(changed);
        assert!(
            f.store
                .create_media_remote(
                    &f.principal,
                    nestlink_protocol::api::MediaRemoteRequest {
                        media_format_version: 2,
                        request: RemoteRequest {
                            id: random_id(),
                            controller_device_id: f.controller_id.clone(),
                            host_device_id: f.host_id.clone(),
                            permissions: vec![1],
                            path_mode: "direct_only".into()
                        },
                    },
                    1000
                )
                .is_err()
        );
    }
    f.store.internal_software_media_candidate = Some(policy);
    f.approve(true, 1001)?;
    let initial = f.store.initial_permit(&f.principal, &f.request_id, 1001)?;
    f.assert_scope(&initial)?;
    assert!(
        f.store
            .current_permit(&f.principal, &f.request_id, 1200)
            .is_err()
    );
    f.store.internal_software_media_candidate = None;
    assert!(
        f.store
            .current_permit(&f.principal, &f.request_id, 1002)
            .is_err()
    );
    // No candidate configuration changes ordinary legacy request creation.
    assert!(
        f.store
            .create_remote(
                &f.principal,
                RemoteRequest {
                    id: random_id(),
                    controller_device_id: f.controller_id.clone(),
                    host_device_id: f.host_id.clone(),
                    permissions: vec![1],
                    path_mode: "direct_only".into(),
                },
                1002
            )
            .is_ok()
    );
    Ok(())
}

#[test]
fn internal_software_candidate_codec_marker_does_not_leak_to_legacy_or_other_targets() -> TestResult
{
    let mut f = MediaLifecycle::new_with_candidate(1_200_000, true)?;
    // Fixture descriptor registration contains only VP8, never a hardware claim.
    f.approve(true, 1001)?;
    let candidate = f.store.initial_permit(&f.principal, &f.request_id, 1001)?;
    assert!(
        candidate
            .required_capabilities
            .iter()
            .any(|value| value == nestlink_protocol::media::H264_CAPABILITY)
    );
    let id = random_id();
    let view = f.store.create_remote(
        &f.principal,
        RemoteRequest {
            id: id.clone(),
            controller_device_id: f.controller_id.clone(),
            host_device_id: f.host_id.clone(),
            permissions: vec![1],
            path_mode: "direct_only".into(),
        },
        1001,
    )?;
    let choice = ApprovalChoice {
        approved: true,
        permissions: vec![1],
        paths: vec![1],
    };
    let proof = f
        .store
        .approval_transcript(&f.principal, &view.id, &choice, 1001)?;
    f.store.approve_remote(
        &f.principal,
        &view.id,
        choice,
        &URL_SAFE_NO_PAD.encode(f.host.sign_action(&proof)?),
        1001,
    )?;
    let legacy = f.store.initial_permit(&f.principal, &view.id, 1001)?;
    assert_eq!(legacy.media_format_version, 0);
    assert!(
        !legacy
            .required_capabilities
            .iter()
            .any(|value| value == nestlink_protocol::media::H264_CAPABILITY)
    );
    let policy = f
        .store
        .internal_software_media_candidate
        .as_ref()
        .ok_or("missing policy")?;
    assert!(policy.authorize_permit(&legacy).is_err());
    let mut wrong = candidate.clone();
    let other = VideoFormat::legacy_h264(31, 640, 480, FrameRate::new(30, 1)?, 2000)?;
    wrong.media_formats = vec![other.encode()?];
    wrong.media_format_sha256 = nestlink_protocol::media_format::FormatSet::new(vec![other])?
        .digest()
        .to_vec();
    assert!(policy.authorize_permit(&wrong).is_err());
    let mut missing_marker = candidate;
    missing_marker
        .required_capabilities
        .retain(|value| value != nestlink_protocol::media::H264_CAPABILITY);
    assert!(policy.authorize_permit(&missing_marker).is_err());
    Ok(())
}
