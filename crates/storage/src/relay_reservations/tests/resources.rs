use super::*;
use nestlink_protocol::{
    NodeResourceQueryClaims, NodeResourceSnapshotClaims, SignedNodeResourceQuery,
};
impl Fixture {
    fn resource_query(&self, now: u64) -> Result<SignedNodeResourceQuery> {
        let (generation,policy,sequence):(u64,u64,u64)=self.s.connection.query_row("SELECT runtime_generation,lease_policy_revision,lease_sequence FROM data_nodes WHERE id=?1",[&self.node_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        Ok(self.node.sign_resource_query(&NodeResourceQueryClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: self.s.deployment_id()?,
            security_epoch: self.s.security_epoch()?,
            node_id: self.node_id.clone(),
            runtime_id: self.node_runtime.clone(),
            runtime_generation: generation,
            policy_revision: policy,
            lease_sequence: sequence,
            request_id: random_id(),
            request_sequence: 1,
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + 1000,
        })?)
    }
    pub(super) fn resource_snapshot(&mut self, now: u64) -> Result<NodeResourceSnapshotClaims> {
        let q = self.resource_query(now)?;
        Ok(self
            .s
            .node_resource_snapshot(&self.lifecycle, &q, &[7; 32], now)?)
    }
    pub(super) fn allocation(&mut self) -> Result<RelayAllocationClaims> {
        let req = self.request(&random_id())?;
        Ok(self.s.reserve_node_relay(
            &self.lifecycle,
            &self.admin,
            &self.permit.session_id,
            req,
            NOW,
        )?)
    }
}
#[test]
fn node_resources_require_node_possession_and_allow_wss_renewal_between_query_and_response()
-> Result {
    let mut f = Fixture::new(false, 8)?;
    let grant = f.allocation()?;
    let q = f.resource_query(NOW)?;
    let first =
        f.s.node_resource_snapshot(&f.lifecycle, &q, &[7; 32], NOW)?;
    assert_eq!(first.allocations, vec![grant.clone()]);
    assert_eq!(first.query_sha256, digest(&q.claims));
    assert_eq!(first.expires_at_unix_ms, NOW + 1000);
    let mut invalid = q.clone();
    invalid.signature[0] ^= 1;
    assert!(
        f.s.node_resource_snapshot(&f.lifecycle, &invalid, &[7; 32], NOW)
            .is_err()
    );
    let next = NOW + nestlink_protocol::NODE_REFRESH_MS;
    let q = f.resource_query(next - 100)?;
    f.at(next);
    let challenge = f.s.node_challenge(&f.node_id, next)?;
    f.s.issue_node_lease(&f.node.prove(&challenge, &f.node_runtime)?, next)?;
    let response =
        f.s.node_resource_snapshot(&f.lifecycle, &q, &[7; 32], next)?;
    assert_eq!(
        response.query,
        Some(nestlink_protocol::decode_bounded(
            &q.claims,
            nestlink_protocol::NODE_MESSAGE_BYTES
        )?)
    );
    assert_eq!(response.allocations, vec![grant]);
    assert_eq!(response.expires_at_unix_ms, next + 900);
    let expired = next + 900;
    f.at(expired);
    assert!(
        f.s.node_resource_snapshot(&f.lifecycle, &q, &[7; 32], expired)
            .is_err()
    );
    Ok(())
}
#[test]
fn revoking_session_account_device_or_login_removes_resources_without_refunding_capacity() -> Result
{
    for change in 0..5 {
        let mut f = Fixture::new(false, 8)?;
        f.allocation()?;
        assert_eq!(f.resource_snapshot(NOW)?.allocations.len(), 1);
        match change {
            0 => f.s.revoke_remote(&f.admin, &f.permit.session_id)?,
            1 => f.s.disable_account(&f.admin, &f.host.account_id)?,
            2 => {
                f.s.revoke_device_as(&f.host, &random_id(), &f.permit.host_device_id, 1001)?;
            }
            3 => {
                f.s.revoke_device_as(&f.admin, &random_id(), &f.permit.controller_device_id, 1001)?;
            }
            _ => {
                f.s.connection.execute(
                    "UPDATE management_sessions SET revoked=1 WHERE id=?1",
                    [&f.admin.session_id],
                )?;
            }
        }
        assert!(
            f.resource_snapshot(NOW)?.allocations.is_empty(),
            "mutation {change}"
        );
        let held: u32 = f.s.connection.query_row(
            "SELECT count(*) FROM relay_reservations WHERE closed=0",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(held, 1);
    }
    Ok(())
}
#[test]
fn policy_quota_restore_and_node_runtime_changes_invalidate_current_resource_authority() -> Result {
    for change in 0..5 {
        let mut f = Fixture::new(false, 8)?;
        f.allocation()?;
        let q = f.resource_query(NOW)?;
        match change {
            0 => {
                f.s.apply_policy(2, NetworkPolicy::default())?;
            }
            1 => {
                f.quota(8, 8)?;
                assert!(f.resource_snapshot(NOW)?.allocations.is_empty());
                continue;
            }
            2 => {
                f.s.revoke_node(&f.admin, &f.node_id)?;
            }
            3 => {
                f.s.invalidate_after_restore()?;
            }
            _ => {
                let challenge = f.s.node_challenge(&f.node_id, NOW)?;
                f.s.issue_node_lease(&f.node.prove(&challenge, &random_id())?, NOW)?;
            }
        }
        assert!(
            f.s.node_resource_snapshot(&f.lifecycle, &q, &[7; 32], NOW)
                .is_err(),
            "mutation {change}"
        );
    }
    Ok(())
}
#[test]
fn snapshots_never_renew_grants_and_omit_expired_or_mismatched_session_permits() -> Result {
    let mut f = Fixture::new(false, 8)?;
    let grant = f.allocation()?;
    let now = NOW + 6000;
    f.renew(now)?;
    assert_eq!(f.resource_snapshot(now)?.allocations, vec![grant.clone()]);
    // Snapshot polling observes facts, it cannot advance the allocation sequence.
    let renewed = f.s.reserve_node_relay(
        &f.lifecycle,
        &f.admin,
        &f.permit.session_id,
        f.request(&grant.allocation_id)?,
        now,
    )?;
    assert_eq!(renewed.grant_sequence, 2);
    assert_eq!(f.resource_snapshot(now)?.allocations, vec![renewed.clone()]);
    let refresh_at = renewed.expires_at_unix_ms - 1000;
    f.at(refresh_at);
    let challenge = f.s.node_challenge(&f.node_id, refresh_at)?;
    f.s.issue_node_lease(&f.node.prove(&challenge, &f.node_runtime)?, refresh_at)?;
    let now = renewed.expires_at_unix_ms;
    f.at(now);
    assert!(f.resource_snapshot(now)?.allocations.is_empty());
    let mut f = Fixture::new(false, 8)?;
    f.allocation()?;
    f.permit.controller_key_sha256 = vec![8; 32];
    f.s.connection.execute(
        "UPDATE remote_requests SET last_permit_json=?1 WHERE id=?2",
        params![serde_json::to_string(&f.permit)?, f.permit.session_id],
    )?;
    assert!(f.resource_snapshot(NOW)?.allocations.is_empty());
    Ok(())
}

#[test]
fn explicit_trust_revocation_removes_the_associated_node_resources() -> Result {
    use nestlink_protocol::api::{TrustChoice, TrustSubmission};
    let mut f = Fixture::new(false, 8)?;
    let choice = TrustChoice {
        expected_revision: 0,
        expires_at_unix_ms: NOW + 60000,
    };
    let signature = URL_SAFE_NO_PAD.encode(f.h.sign_action(
        &nestlink_identity::trust_transcript(&f.permit, &f.host.account_id, &choice)?,
    )?);
    f.s.trust_remote(
        &f.host,
        &f.permit.session_id,
        TrustSubmission { choice, signature },
        NOW / 1000,
    )?;
    let remote = f.s.create_trusted_remote(
        &f.admin,
        RemoteRequest {
            id: random_id(),
            controller_device_id: f.permit.controller_device_id.clone(),
            host_device_id: f.permit.host_device_id.clone(),
            permissions: f.permit.permissions.clone(),
            path_mode: "relay_only".into(),
        },
        NOW / 1000,
    )?;
    f.permit = f.s.initial_permit(&f.admin, &remote.id, NOW / 1000)?;
    f.allocation()?;
    assert_eq!(f.resource_snapshot(NOW)?.allocations.len(), 1);
    f.s.revoke_device_trust(
        &f.host,
        &f.permit.host_device_id,
        &f.permit.controller_device_id,
        1,
        NOW / 1000,
    )?;
    assert!(f.resource_snapshot(NOW)?.allocations.is_empty());
    assert_eq!(f.usage(NOW)?.held_allocations, 1);
    Ok(())
}

#[test]
fn fixed_password_revocation_removes_the_associated_node_resources() -> Result {
    use nestlink_identity::remote_password::{configure_transcript, use_transcript};
    use nestlink_protocol::api::{
        RemotePasswordAttempt, RemotePasswordChoice, RemotePasswordSettings, RemotePasswordSetup,
        RemotePasswordSubmission,
    };
    let mut f = Fixture::new(false, 8)?;
    let password = "node-resource-remote-test-password";
    let challenge = f.s.enrollment_challenge(&f.host, NOW / 1000)?;
    let choice = RemotePasswordChoice {
        settings: RemotePasswordSettings {
            expected_revision: 0,
            permissions: f.permit.permissions.clone(),
            paths: f.permit.paths.clone(),
            expires_at_unix_ms: NOW + 60000,
        },
        password: password.into(),
    };
    let signature = URL_SAFE_NO_PAD.encode(f.h.sign_action(&configure_transcript(
        &challenge,
        &f.host.account_id,
        &f.permit.host_device_id,
        &choice,
    )?)?);
    let draft = f.s.prepare_remote_password(
        &f.host,
        &f.permit.host_device_id,
        RemotePasswordSetup {
            challenge_id: challenge.id,
            choice,
            signature,
        },
        NOW / 1000,
    )?;
    f.s.complete_remote_password(draft.derive()?, NOW / 1000)?;
    let remote = f.s.create_remote(
        &f.admin,
        RemoteRequest {
            id: random_id(),
            controller_device_id: f.permit.controller_device_id.clone(),
            host_device_id: f.permit.host_device_id.clone(),
            permissions: f.permit.permissions.clone(),
            path_mode: "relay_only".into(),
        },
        NOW / 1000,
    )?;
    let attempt = RemotePasswordAttempt {
        expected_revision: 1,
        password: password.into(),
    };
    let signature = URL_SAFE_NO_PAD.encode(f.c.sign_action(&use_transcript(
        &f.s.deployment_id()?,
        f.s.security_epoch()?,
        &f.admin.account_id,
        &remote,
        &attempt,
    )?)?);
    let verification =
        f.s.remote_password_snapshot(
            &f.admin,
            &remote.id,
            RemotePasswordSubmission { attempt, signature },
            NOW / 1000,
        )?
        .verify();
    f.s.complete_remote_password_access(verification, NOW / 1000)?;
    f.permit = f.s.initial_permit(&f.admin, &remote.id, NOW / 1000)?;
    // Password derivation uses real CPU time; this fixture's clock is simulated.
    f.at(NOW);
    f.allocation()?;
    assert_eq!(f.resource_snapshot(NOW)?.allocations.len(), 1);
    f.s.revoke_remote_password(&f.host, &f.permit.host_device_id, 1, NOW / 1000)?;
    assert!(f.resource_snapshot(NOW)?.allocations.is_empty());
    assert_eq!(f.usage(NOW)?.held_allocations, 1);
    Ok(())
}
