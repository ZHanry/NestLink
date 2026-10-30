use super::*;
use nestlink_identity::reconnection::transcript;
use nestlink_protocol::{
    PermitClaims,
    api::{ReconnectionApproval, ReconnectionChoice, ReconnectionOffer, ReconnectionSubmission},
};
use prost::Message;
struct Fixture {
    store: Store,
    controller: InstallationIdentity,
    host: InstallationIdentity,
    admin: Principal,
    member: Principal,
    permit: PermitClaims,
}
impl Fixture {
    fn new() -> Result<Self> {
        let (mut store, _, _, admin, member) = fixture()?;
        let controller = InstallationIdentity::generate();
        let host = InstallationIdentity::generate();
        let c = enroll(&mut store, &admin, &controller, "controller")?;
        let h = enroll(&mut store, &member, &host, "host")?;
        let view = store.create_remote(
            &admin,
            RemoteRequest {
                id: random_id(),
                controller_device_id: c,
                host_device_id: h,
                permissions: vec![1, 2],
                path_mode: "direct_only".into(),
            },
            1000,
        )?;
        let choice = ApprovalChoice {
            approved: true,
            permissions: vec![1],
            paths: vec![1],
        };
        let proof = store.approval_transcript(&member, &view.id, &choice, 1001)?;
        store.approve_remote(
            &member,
            &view.id,
            choice,
            &URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
            1001,
        )?;
        let permit = store.initial_permit(&admin, &view.id, 1002)?;
        Ok(Self {
            store,
            controller,
            host,
            admin,
            member,
            permit,
        })
    }
    fn submission(&self, nonce: u8) -> Result<ReconnectionSubmission> {
        let p = &self.permit;
        let choice = ReconnectionChoice {
            previous_permit_sha256: URL_SAFE_NO_PAD
                .encode(nestlink_identity::digest(&p.encode_to_vec())),
            connection_generation: p.connection_generation + 1,
            lease_sequence: p.lease_sequence + 1,
            nonce: URL_SAFE_NO_PAD.encode([nonce; 32]),
        };
        Ok(ReconnectionSubmission {
            controller_signature: URL_SAFE_NO_PAD.encode(
                self.controller
                    .sign_action(&transcript(p, &p.controller_device_id, &choice)?)?,
            ),
            host_signature: URL_SAFE_NO_PAD.encode(self.host.sign_action(&transcript(
                p,
                &p.host_device_id,
                &choice,
            )?)?),
            choice,
        })
    }
}
#[test]
fn reconnect_advances_both_generations_and_lost_response_retries_preserve_exact_lease() -> Result {
    let mut f = Fixture::new()?;
    let body = f.submission(9)?;
    let id = f.permit.session_id.clone();
    let before = f.store.audit_count()?;
    let next = f
        .store
        .reconnect_permit(&f.admin, &id, body.clone(), 1004)?
        .next;
    assert_eq!(next.connection_generation, 2);
    assert_eq!(next.lease_sequence, 2);
    nestlink_identity::reconnection::validate_successor(&f.permit, &next, &body.choice)?;
    assert_eq!(next.expires_at_unix_ms, f.permit.expires_at_unix_ms);
    assert_eq!(next.permissions, vec![1]);
    assert_eq!(
        f.store
            .reconnect_permit(&f.admin, &id, body.clone(), 1005)?
            .next,
        next
    );
    assert_eq!(f.store.audit_count()?, before + 1);
    assert_eq!(f.store.remote(&f.admin, &id)?.connection_generation, 2);
    assert_eq!(f.store.current_permit(&f.member, &id, 1005)?, next);
    assert!(
        f.store
            .reconnect_permit(&f.admin, &id, f.submission(10)?, 1005)
            .is_err()
    );
    let cp = f.store.renewal_transcript(&f.admin, &id, 3, false, 1006)?;
    let hp = f.store.renewal_transcript(&f.admin, &id, 3, true, 1006)?;
    f.store.renew_permit(
        &f.admin,
        &id,
        RenewalSubmission {
            lease_sequence: 3,
            controller_signature: URL_SAFE_NO_PAD.encode(f.controller.sign_action(&cp)?),
            host_signature: URL_SAFE_NO_PAD.encode(f.host.sign_action(&hp)?),
        },
        1006,
    )?;
    assert!(f.store.reconnect_permit(&f.admin, &id, body, 1006).is_err());
    assert!(
        f.store
            .reconnection_state(&f.member, &id, 1006)?
            .1
            .is_none()
    );
    Ok(())
}
#[test]
fn coordinated_proofs_enforce_login_account_choice_and_do_not_replace_active_offer() -> Result {
    let mut f = Fixture::new()?;
    let body = f.submission(11)?;
    let id = f.permit.session_id.clone();
    let offer = ReconnectionOffer {
        choice: body.choice.clone(),
        controller_signature: body.controller_signature.clone(),
    };
    assert!(
        f.store
            .offer_reconnection(&f.member, &id, offer.clone(), 1004)
            .is_err()
    );
    f.store
        .offer_reconnection(&f.admin, &id, offer.clone(), 1004)?;
    f.store.offer_reconnection(&f.admin, &id, offer, 1005)?;
    let other = f.submission(12)?;
    assert!(
        f.store
            .offer_reconnection(
                &f.admin,
                &id,
                ReconnectionOffer {
                    choice: other.choice.clone(),
                    controller_signature: other.controller_signature
                },
                1005
            )
            .is_err()
    );
    assert!(
        f.store
            .approve_reconnection(
                &f.admin,
                &id,
                ReconnectionApproval {
                    choice: body.choice.clone(),
                    host_signature: body.host_signature.clone()
                },
                1005
            )
            .is_err()
    );
    assert!(
        f.store
            .approve_reconnection(
                &f.member,
                &id,
                ReconnectionApproval {
                    choice: other.choice,
                    host_signature: other.host_signature
                },
                1005
            )
            .is_err()
    );
    f.store.approve_reconnection(
        &f.member,
        &id,
        ReconnectionApproval {
            choice: body.choice.clone(),
            host_signature: body.host_signature.clone(),
        },
        1005,
    )?;
    let state = f.store.reconnection_state(&f.admin, &id, 1005)?.0;
    assert_eq!(
        state.host_signature.as_deref(),
        Some(body.host_signature.as_str())
    );
    f.store
        .reconnect_permit(&f.admin, &id, body.clone(), 1005)?;
    assert!(
        f.store
            .reconnection_state(&f.member, &id, 1005)?
            .1
            .is_some()
    );
    f.permit = f.store.current_permit(&f.admin, &id, 1005)?;
    let next = f.submission(13)?;
    f.store.offer_reconnection(
        &f.admin,
        &id,
        ReconnectionOffer {
            choice: next.choice.clone(),
            controller_signature: next.controller_signature,
        },
        1006,
    )?;
    let (state, receipt) = f.store.reconnection_state(&f.member, &id, 1006)?;
    assert!(receipt.is_none());
    assert_eq!(state.offer.ok_or("missing offer")?.choice, next.choice);
    Ok(())
}
#[test]
fn reconnect_rejects_bad_proofs_stale_digest_wrong_generation_and_new_controller_login() -> Result {
    let mut f = Fixture::new()?;
    let id = f.permit.session_id.clone();
    let body = f.submission(14)?;
    let (vault, dummy) = (
        VaultKey::from_bytes([7; 32]),
        hash_password("dummy-only-password")?,
    );
    let login = f
        .store
        .login("admin", PASSWORD, None, 1004, &vault, &dummy)?
        .principal;
    assert!(
        f.store
            .reconnect_permit(&login, &id, body.clone(), 1004)
            .is_err()
    );
    for variant in 0..5 {
        let mut b = body.clone();
        match variant {
            0 => b.host_signature = b.controller_signature.clone(),
            1 => b.controller_signature = b.host_signature.clone(),
            2 => b.choice.nonce = URL_SAFE_NO_PAD.encode([19; 32]),
            3 => b.choice.previous_permit_sha256 = URL_SAFE_NO_PAD.encode([0; 32]),
            _ => b.choice.connection_generation = 3,
        };
        assert!(f.store.reconnect_permit(&f.admin, &id, b, 1004).is_err());
        assert_eq!(f.store.current_permit(&f.admin, &id, 1004)?, f.permit);
    }
    Ok(())
}
#[test]
fn revoked_expired_disabled_and_restored_resources_never_replay_receipts() -> Result {
    for variant in 0..5 {
        let mut f = Fixture::new()?;
        let body = f.submission(20)?;
        let id = f.permit.session_id.clone();
        f.store
            .reconnect_permit(&f.admin, &id, body.clone(), 1004)?;
        let now = match variant {
            0 => {
                f.store.revoke_remote(&f.member, &id)?;
                1005
            }
            1 => {
                f.store.disable_account(&f.admin, &f.member.account_id)?;
                1005
            }
            2 => {
                f.store.logout(&f.admin)?;
                1005
            }
            3 => {
                f.store.invalidate_after_restore()?;
                1005
            }
            _ => f.permit.expires_at_unix_ms / 1000,
        };
        assert!(f.store.reconnect_permit(&f.admin, &id, body, now).is_err());
        assert!(f.store.reconnection_state(&f.member, &id, now).is_err());
    }
    Ok(())
}
#[test]
fn independent_sqlite_writers_have_one_generation_winner() -> Result {
    let f = Fixture::new()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("control.sqlite3");
    std::fs::write(&path, f.store.snapshot()?.as_slice())?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut threads = vec![];
    for nonce in [25, 26] {
        let path = path.clone();
        let deployment = f.permit.deployment_id.clone();
        let actor = f.admin.clone();
        let id = f.permit.session_id.clone();
        let body = f.submission(nonce)?;
        let barrier = barrier.clone();
        // Initialize both connections before the barrier; a failed open must not strand a peer.
        let mut store = Store::open_existing(&path, &deployment)?;
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            store
                .reconnect_permit(&actor, &id, body, 1004)
                .map(|r| r.next)
        }));
    }
    let mut winners = vec![];
    for thread in threads {
        if let Ok(permit) = thread.join().map_err(|_| "writer panicked")? {
            winners.push(permit);
        }
    }
    assert_eq!(winners.len(), 1);
    let store = Store::open_existing(&path, &f.permit.deployment_id)?;
    assert_eq!(
        store.current_permit(&f.admin, &f.permit.session_id, 1004)?,
        winners[0]
    );
    Ok(())
}
#[test]
fn reconnect_clears_old_signals_accepts_new_sequence_and_policy_update_kills_receipt() -> Result {
    let mut f = Fixture::new()?;
    let id = f.permit.session_id.clone();
    let submission = |permit: &PermitClaims,
                      sequence: u64|
     -> Result<nestlink_protocol::api::SignalSubmission> {
        let payload = nestlink_protocol::api::SignalPayload {
            rendezvous: None,
            ice: None,
            connection_generation: permit.connection_generation,
            lease_sequence: permit.lease_sequence,
            network_generation: 1,
            sequence,
            candidates: vec![nestlink_protocol::api::Candidate {
                address: "203.0.113.10:28741".parse()?,
                transport: nestlink_protocol::api::Transport::Quic,
                kind: nestlink_protocol::api::CandidateKind::Lan,
                generation: 1,
            }],
            description: None,
        };
        let proof = nestlink_identity::signal_transcript(
            permit,
            &f.admin.account_id,
            &permit.controller_device_id,
            &payload,
        )?;
        Ok(nestlink_protocol::api::SignalSubmission {
            device_id: permit.controller_device_id.clone(),
            payload,
            signature: URL_SAFE_NO_PAD.encode(f.controller.sign_action(&proof)?),
        })
    };
    let old = submission(&f.permit, 5)?;
    f.store.submit_signal(&f.admin, &id, old.clone(), 1003)?;
    assert_eq!(f.store.remote_signals(&f.member, &id, 1003)?.len(), 1);
    let body = f.submission(27)?;
    let next = f
        .store
        .reconnect_permit(&f.admin, &id, body.clone(), 1004)?
        .next;
    assert!(f.store.remote_signals(&f.member, &id, 1004)?.is_empty());
    assert!(f.store.submit_signal(&f.admin, &id, old, 1004).is_err());
    f.store
        .submit_signal(&f.admin, &id, submission(&next, 1)?, 1004)?;
    assert_eq!(f.store.remote_signals(&f.member, &id, 1004)?.len(), 1);
    let (revision, policy) = f.store.policy()?;
    f.store.apply_policy(revision, policy)?;
    assert!(f.store.reconnect_permit(&f.admin, &id, body, 1005).is_err());
    Ok(())
}
#[test]
fn audit_exhaustion_rolls_back_generation_receipt_and_signal_cleanup() -> Result {
    let mut f = Fixture::new()?;
    let body = f.submission(28)?;
    let id = f.permit.session_id.clone();
    let mut view = rusqlite::Connection::open_in_memory()?;
    let bytes = f.store.snapshot()?;
    view.deserialize_read_exact(rusqlite::MAIN_DB, &bytes[..], bytes.len(), false)?;
    view.execute(
        "UPDATE audit_settings SET high_watermark=9223372036854775807",
        [],
    )?;
    let bytes = view.serialize(rusqlite::MAIN_DB)?;
    f.store = Store::from_snapshot(&bytes, &f.permit.deployment_id)?;
    assert!(f.store.reconnect_permit(&f.admin, &id, body, 1004).is_err());
    assert_eq!(f.store.current_permit(&f.admin, &id, 1004)?, f.permit);
    assert_eq!(f.store.remote(&f.admin, &id)?.connection_generation, 1);
    assert!(
        f.store
            .reconnection_state(&f.member, &id, 1004)?
            .1
            .is_none()
    );
    Ok(())
}
