use super::*;
use nestlink_identity::remote_password::{configure_transcript, use_transcript};
use nestlink_protocol::api::*;
use nestlink_storage::remote_password::{RemotePasswordDraft, RemotePasswordSnapshot};

const REMOTE_SECRET: &str = "remote-only-test-password";
struct Setup {
    s: Store,
    vault: VaultKey,
    dummy: String,
    admin: Principal,
    owner: Principal,
    c: InstallationIdentity,
    h: InstallationIdentity,
    cid: String,
    hid: String,
}
impl Setup {
    fn new() -> Result<Self> {
        let (mut s, vault, dummy, admin, owner) = fixture()?;
        let c = InstallationIdentity::generate();
        let h = InstallationIdentity::generate();
        let cid = enroll(&mut s, &admin, &c, "controller")?;
        let hid = enroll(&mut s, &owner, &h, "host")?;
        Ok(Self {
            s,
            vault,
            dummy,
            admin,
            owner,
            c,
            h,
            cid,
            hid,
        })
    }
    fn body(&mut self, revision: u64, expires: u64, now: u64) -> Result<RemotePasswordSetup> {
        let challenge = self.s.enrollment_challenge(&self.owner, now)?;
        let choice = RemotePasswordChoice {
            settings: RemotePasswordSettings {
                expected_revision: revision,
                permissions: vec![Permission::View as i32],
                paths: vec![1],
                expires_at_unix_ms: expires,
            },
            password: REMOTE_SECRET.into(),
        };
        let proof = configure_transcript(&challenge, &self.owner.account_id, &self.hid, &choice)?;
        Ok(RemotePasswordSetup {
            challenge_id: challenge.id,
            choice,
            signature: URL_SAFE_NO_PAD.encode(self.h.sign_action(&proof)?),
        })
    }
    fn draft(&mut self, revision: u64, expires: u64, now: u64) -> Result<RemotePasswordDraft> {
        let body = self.body(revision, expires, now)?;
        Ok(self
            .s
            .prepare_remote_password(&self.owner, &self.hid, body, now)?)
    }
    fn configure(&mut self, revision: u64, expires: u64, now: u64) -> Result {
        let replacement = self.draft(revision, expires, now)?.derive()?;
        assert_eq!(
            self.s.complete_remote_password(replacement, now)?.revision,
            revision + 1
        );
        Ok(())
    }
    fn request(&mut self, now: u64) -> Result<RemoteView> {
        Ok(self.s.create_remote(
            &self.admin,
            RemoteRequest {
                id: random_id(),
                controller_device_id: self.cid.clone(),
                host_device_id: self.hid.clone(),
                permissions: vec![Permission::View as i32],
                path_mode: "direct_preferred".into(),
            },
            now,
        )?)
    }
    fn proof(
        &self,
        view: &RemoteView,
        revision: u64,
        password: &str,
    ) -> Result<RemotePasswordSubmission> {
        let attempt = RemotePasswordAttempt {
            expected_revision: revision,
            password: password.into(),
        };
        let proof = use_transcript(
            &self.s.deployment_id()?,
            self.s.security_epoch()?,
            &self.admin.account_id,
            view,
            &attempt,
        )?;
        Ok(RemotePasswordSubmission {
            attempt,
            signature: URL_SAFE_NO_PAD.encode(self.c.sign_action(&proof)?),
        })
    }
    fn snapshot(
        &mut self,
        view: &RemoteView,
        revision: u64,
        password: &str,
        now: u64,
    ) -> Result<RemotePasswordSnapshot> {
        let proof = self.proof(view, revision, password)?;
        Ok(self
            .s
            .remote_password_snapshot(&self.admin, &view.id, proof, now)?)
    }
}
#[test]
fn configuration_requires_host_key_explicit_scope_and_one_use_challenge() -> Result {
    let mut f = Setup::new()?;
    let body = f.body(0, 1_100_000, 1000)?;
    assert!(
        f.s.prepare_remote_password(&f.admin, &f.hid, body, 1000)
            .is_err()
    );
    let mut body = f.body(0, 1_100_000, 1000)?;
    body.choice
        .settings
        .permissions
        .push(Permission::Input as i32);
    assert!(
        f.s.prepare_remote_password(&f.owner, &f.hid, body, 1000)
            .is_err()
    );
    let mut body = f.body(0, 1_100_000, 1000)?;
    body.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert!(
        f.s.prepare_remote_password(&f.owner, &f.hid, body, 1000)
            .is_err()
    );
    let mut body = f.body(0, 1_100_000, 1000)?;
    body.choice.password = "short".into();
    assert!(
        f.s.prepare_remote_password(&f.owner, &f.hid, body, 1000)
            .is_err()
    );
    let body = f.body(
        0,
        1_000_000 + nestlink_storage::remote_password::MAX_PASSWORD_MS + 1,
        1000,
    )?;
    assert!(
        f.s.prepare_remote_password(&f.owner, &f.hid, body, 1000)
            .is_err()
    );
    let body = f.body(0, 1_100_000, 1000)?;
    let replay: RemotePasswordSetup = serde_json::from_slice(&serde_json::to_vec(&body)?)?;
    let draft = f.s.prepare_remote_password(&f.owner, &f.hid, body, 1000)?;
    f.s.complete_remote_password(draft.derive()?, 1000)?;
    assert!(
        f.s.prepare_remote_password(&f.owner, &f.hid, replay, 1000)
            .is_err()
    );
    assert!(f.s.remote_password(&f.admin, &f.hid, 1000).is_err());
    let snapshot = f.s.snapshot()?;
    assert!(
        !snapshot
            .windows(REMOTE_SECRET.len())
            .any(|w| w == REMOTE_SECRET.as_bytes())
    );
    let view = f.request(1001)?;
    assert_eq!(view.status, "pending");
    assert!(f.s.initial_permit(&f.admin, &view.id, 1001).is_err());
    Ok(())
}
#[test]
fn password_proof_is_controller_bound_and_permits_are_scoped_and_expiring() -> Result {
    let mut f = Setup::new()?;
    let (revision, mut policy) = f.s.policy()?;
    policy.server_forwarding = nestlink_policy::ServerForwarding::Allow;
    policy.peer_path_mode = nestlink_policy::PeerPathMode::DirectPreferred;
    f.s.apply_policy(revision, policy)?;
    f.configure(0, 1_010_000, 1000)?;
    let view = f.request(1001)?;
    assert_eq!(view.paths, vec![1, 2]);
    let bad = f.proof(&view, 1, REMOTE_SECRET)?;
    assert!(
        f.s.remote_password_snapshot(&f.owner, &view.id, bad, 1001)
            .is_err()
    );
    let mut bad = f.proof(&view, 1, REMOTE_SECRET)?;
    let mut transcript = use_transcript(
        &f.s.deployment_id()?,
        f.s.security_epoch()?,
        &f.admin.account_id,
        &view,
        &bad.attempt,
    )?;
    transcript.action = nestlink_protocol::DeviceAction::Approve as i32;
    bad.signature = URL_SAFE_NO_PAD.encode(f.c.sign_action(&transcript)?);
    assert!(
        f.s.remote_password_snapshot(&f.admin, &view.id, bad, 1001)
            .is_err()
    );
    let wrong = f.snapshot(&view, 1, "wrong-password", 1001)?.verify();
    assert!(matches!(
        f.s.complete_remote_password_access(wrong, 1001),
        Err(StorageError::Unauthorized)
    ));
    let verified = f.snapshot(&view, 1, REMOTE_SECRET, 1001)?.verify();
    let approved = f.s.complete_remote_password_access(verified, 1001)?;
    assert_eq!(approved.password_revision, Some(1));
    assert_eq!(approved.trust_revision, None);
    assert_eq!(approved.paths, vec![1]);
    let first = f.s.initial_permit(&f.admin, &view.id, 1002)?;
    assert_eq!(first.expires_at_unix_ms, 1_010_000);
    let cp = f.s.renewal_transcript(&f.admin, &view.id, 2, false, 1005)?;
    let hp = f.s.renewal_transcript(&f.admin, &view.id, 2, true, 1005)?;
    assert_eq!(cp.expires_at_unix_ms, first.expires_at_unix_ms);
    let renewed = f.s.renew_permit(
        &f.admin,
        &view.id,
        RenewalSubmission {
            lease_sequence: 2,
            controller_signature: URL_SAFE_NO_PAD.encode(f.c.sign_action(&cp)?),
            host_signature: URL_SAFE_NO_PAD.encode(f.h.sign_action(&hp)?),
        },
        1005,
    )?;
    assert_eq!(renewed.expires_at_unix_ms, first.expires_at_unix_ms);
    assert!(f.s.current_permit(&f.admin, &view.id, 1010).is_err());
    assert!(
        f.s.renewal_transcript(&f.admin, &view.id, 3, false, 1010)
            .is_err()
    );
    let excessive = f.s.create_remote(
        &f.admin,
        RemoteRequest {
            id: random_id(),
            controller_device_id: f.cid.clone(),
            host_device_id: f.hid.clone(),
            permissions: vec![Permission::View as i32, Permission::Input as i32],
            path_mode: "direct_only".into(),
        },
        1002,
    )?;
    let forged = f.proof(&excessive, 1, REMOTE_SECRET)?;
    assert!(
        f.s.remote_password_snapshot(&f.admin, &excessive.id, forged, 1002)
            .is_err()
    );
    let relay = f.s.create_remote(
        &f.admin,
        RemoteRequest {
            id: random_id(),
            controller_device_id: f.cid.clone(),
            host_device_id: f.hid.clone(),
            permissions: vec![Permission::View as i32],
            path_mode: "relay_only".into(),
        },
        1002,
    )?;
    let forbidden = f.proof(&relay, 1, REMOTE_SECRET)?;
    assert!(matches!(
        f.s.remote_password_snapshot(&f.admin, &relay.id, forbidden, 1002),
        Err(StorageError::Forbidden)
    ));
    Ok(())
}
#[test]
fn revision_tombstones_cancel_inflight_hashes_and_old_sessions() -> Result {
    let mut f = Setup::new()?;
    f.configure(0, 1_100_000, 1000)?;
    let view = f.request(1001)?;
    let verified = f.snapshot(&view, 1, REMOTE_SECRET, 1001)?.verify();
    f.s.complete_remote_password_access(verified, 1001)?;
    f.s.initial_permit(&f.admin, &view.id, 1001)?;
    let pending = f.request(1001)?;
    let delayed = f.snapshot(&pending, 1, REMOTE_SECRET, 1001)?.verify();
    let replacement = f.draft(1, 1_100_000, 1001)?.derive()?;
    let revoked = f.s.revoke_remote_password(&f.owner, &f.hid, 1, 1002)?;
    assert_eq!(revoked.revision, 2);
    assert_eq!(revoked.revoked_sessions, vec![view.id.clone()]);
    assert!(f.s.complete_remote_password_access(delayed, 1002).is_err());
    assert!(f.s.complete_remote_password(replacement, 1002).is_err());
    f.configure(2, 1_100_000, 1003)?;
    assert!(
        f.s.revoke_remote_password(&f.owner, &f.hid, 1, 1003)
            .is_err()
    );
    assert!(f.s.current_permit(&f.admin, &view.id, 1003).is_err());
    assert!(f.snapshot(&pending, 1, REMOTE_SECRET, 1003).is_err());
    let first = f.snapshot(&pending, 3, REMOTE_SECRET, 1003)?.verify();
    let second = f.snapshot(&pending, 3, REMOTE_SECRET, 1003)?.verify();
    f.s.complete_remote_password_access(first, 1003)?;
    assert!(f.s.complete_remote_password_access(second, 1003).is_err());
    Ok(())
}
#[test]
fn attempt_reservations_survive_cancellation_snapshot_login_and_rotation() -> Result {
    let mut f = Setup::new()?;
    f.configure(0, 1_200_000, 1000)?;
    let deployment = f.s.deployment_id()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("password-rate.sqlite3");
    std::fs::write(&path, &*f.s.snapshot()?)?;
    f.s = Store::open_existing(&path, &deployment)?;
    let view = f.request(1001)?;
    for _ in 0..5 {
        drop(f.snapshot(&view, 1, REMOTE_SECRET, 1001)?);
    }
    let proof = f.proof(&view, 1, REMOTE_SECRET)?;
    assert!(matches!(
        f.s.remote_password_snapshot(&f.admin, &view.id, proof, 1001),
        Err(StorageError::RateLimited)
    ));
    // Close the actual SQLite connection, reopen it, then check a snapshot too.
    f.s = Store::in_memory(&random_id())?;
    f.s = Store::open_existing(&path, &deployment)?;
    f.s = Store::from_snapshot(&f.s.snapshot()?, &deployment)?;
    let page = f.s.query_audit(
        &f.admin,
        AuditQuery {
            security_epoch: f.s.security_epoch()?,
            after_sequence: 0,
            limit: 100,
        },
        1002,
    )?;
    let attempts: Vec<_> = page
        .entries
        .iter()
        .filter(|e| e.event == "remote_password_attempted")
        .collect();
    assert_eq!(attempts.len(), 5);
    let expected = AuditActor::Device {
        account_id: f.admin.account_id.clone(),
        session_id: f.admin.session_id.clone(),
        device_id: f.cid.clone(),
    };
    assert!(
        attempts
            .iter()
            .all(|e| e.resource_id == view.id && e.actor == expected)
    );
    assert!(!page.entries.iter().any(|e| e.event == "remote_password_failed" || e.event == "remote_password_authorized"));
    assert!(!serde_json::to_string(&page)?.contains(REMOTE_SECRET));
    let other = InstallationIdentity::generate();
    let other_id = enroll(&mut f.s, &f.owner, &other, "second-account-controller")?;
    let other_view = f.s.create_remote(
        &f.owner,
        RemoteRequest {
            id: random_id(),
            controller_device_id: other_id,
            host_device_id: f.hid.clone(),
            permissions: vec![Permission::View as i32],
            path_mode: "direct_only".into(),
        },
        1002,
    )?;
    let attempt = RemotePasswordAttempt {
        expected_revision: 1,
        password: REMOTE_SECRET.into(),
    };
    let proof = use_transcript(
        &deployment,
        f.s.security_epoch()?,
        &f.owner.account_id,
        &other_view,
        &attempt,
    )?;
    let submission = RemotePasswordSubmission {
        attempt,
        signature: URL_SAFE_NO_PAD.encode(other.sign_action(&proof)?),
    };
    assert!(matches!(
        f.s.remote_password_snapshot(&f.owner, &other_view.id, submission, 1002),
        Err(StorageError::RateLimited)
    ));
    f.configure(1, 1_200_000, 1002)?;
    let login =
        f.s.login("admin", PASSWORD, None, 1002, &f.vault, &f.dummy)?;
    let refreshed =
        f.s.refresh_login(login.refresh_token.expose(), login.generation, 1002)?;
    f.admin = refreshed.principal;
    let view = f.request(1002)?;
    let proof = f.proof(&view, 2, REMOTE_SECRET)?;
    assert!(matches!(
        f.s.remote_password_snapshot(&f.admin, &view.id, proof, 1002),
        Err(StorageError::RateLimited)
    ));
    let view = f.request(1061)?;
    drop(f.snapshot(&view, 2, REMOTE_SECRET, 1061)?);
    let proof = f.proof(&view, 2, REMOTE_SECRET)?;
    assert!(matches!(
        f.s.remote_password_snapshot(&f.admin, &view.id, proof, 1060),
        Err(StorageError::RateLimited)
    ));
    Ok(())
}
#[test]
fn account_budget_spans_devices_and_hashes_complete_only_in_original_context() -> Result {
    let mut f = Setup::new()?;
    for host in 0..7 {
        f.h = InstallationIdentity::generate();
        f.hid = enroll(&mut f.s, &f.owner, &f.h, &format!("host-{host}"))?;
        f.configure(0, 1_200_000, 1000)?;
        let view = f.request(1001)?;
        if host < 6 {
            for _ in 0..5 {
                drop(f.snapshot(&view, 1, REMOTE_SECRET, 1001)?);
            }
        } else {
            let proof = f.proof(&view, 1, REMOTE_SECRET)?;
            assert!(matches!(
                f.s.remote_password_snapshot(&f.admin, &view.id, proof, 1001),
                Err(StorageError::RateLimited)
            ));
        }
    }
    // Login/refresh cannot reset the persistent per-account budget either.
    f.admin =
        f.s.login("admin", PASSWORD, None, 1002, &f.vault, &f.dummy)?
            .principal;
    let view = f.request(1002)?;
    let proof = f.proof(&view, 1, REMOTE_SECRET)?;
    assert!(matches!(
        f.s.remote_password_snapshot(&f.admin, &view.id, proof, 1002),
        Err(StorageError::RateLimited)
    ));
    let view = f.request(1061)?;
    let verified = f.snapshot(&view, 1, REMOTE_SECRET, 1061)?.verify();
    f.s.logout(&f.admin)?;
    assert!(f.s.complete_remote_password_access(verified, 1061).is_err());
    Ok(())
}
#[test]
fn password_work_rechecks_refresh_restore_policy_and_device_keys() -> Result {
    let mut f = Setup::new()?;
    f.configure(0, 1_200_000, 1000)?;
    let login =
        f.s.login("member", PASSWORD, None, 1000, &f.vault, &f.dummy)?;
    f.owner = login.principal;
    let delayed = f.draft(1, 1_200_000, 1001)?.derive()?;
    f.s.refresh_login(login.refresh_token.expose(), login.generation, 1001)?;
    assert!(f.s.complete_remote_password(delayed, 1001).is_err());
    let view = f.request(1001)?;
    let verified = f.snapshot(&view, 1, REMOTE_SECRET, 1001)?.verify();
    let (revision, policy) = f.s.policy()?;
    f.s.apply_policy(revision, policy)?;
    assert!(f.s.complete_remote_password_access(verified, 1002).is_err());
    let view = f.request(1002)?;
    let verified = f.snapshot(&view, 1, REMOTE_SECRET, 1002)?.verify();
    f.s.complete_remote_password_access(verified, 1002)?;
    f.s.initial_permit(&f.admin, &view.id, 1002)?;
    let bytes = f.s.snapshot()?;
    let deployment = f.s.deployment_id()?;
    for host in [false, true] {
        let mut db = rusqlite::Connection::open_in_memory()?;
        db.deserialize_read_exact(rusqlite::MAIN_DB, &bytes[..], bytes.len(), false)?;
        let key = InstallationIdentity::generate();
        let id = if host { &f.hid } else { &f.cid };
        db.execute(
            "UPDATE devices SET key_sha256=?1 WHERE id=?2",
            rusqlite::params![key.fingerprint(), id],
        )?;
        db.execute(
            "UPDATE device_details SET public_key=?1 WHERE device_id=?2",
            rusqlite::params![key.public_key(), id],
        )?;
        let mutated = db.serialize(rusqlite::MAIN_DB)?;
        let store = Store::from_snapshot(&mutated, &deployment)?;
        assert!(store.current_permit(&f.admin, &view.id, 1003).is_err());
    }
    f.s.invalidate_after_restore()?;
    let new_owner =
        f.s.login("member", PASSWORD, None, 1003, &f.vault, &f.dummy)?
            .principal;
    assert!(!f.s.remote_password(&new_owner, &f.hid, 1003)?.active);
    assert!(f.s.current_permit(&f.admin, &view.id, 1003).is_err());
    Ok(())
}
