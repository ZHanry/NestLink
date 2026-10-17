use super::*;
use nestlink_identity::turn::{credential_request_transcript, verify_turn_resource_snapshot};
use nestlink_protocol::{
    SignedTurnResourceQuery, TurnGrantClaims, TurnPeerBindingClaims, TurnPurpose,
    TurnResourceQueryClaims,
    api::{
        BrowserEndpointRegistration, DeviceRegistration, TurnCredentialRequest, TurnEndpointConfig,
        TurnEndpointsUpdate, TurnPeerSubmission,
    },
};
use prost::Message;
impl Fixture {
    fn browser_turn() -> Result<Self> {
        Self::browser_turn_with_registration(false)
    }

    fn permanent_browser_turn() -> Result<Self> {
        Self::browser_turn_with_registration(true)
    }

    fn browser_turn_with_registration(permanent: bool) -> Result<Self> {
        let mut f = Self::new(false, 8)?;
        let browser = InstallationIdentity::generate();
        let endpoint_id =
            if permanent {
                let challenge = f.s.enrollment_challenge(&f.admin, 1000)?;
                let mut registration = DeviceRegistration {
                    challenge_id: challenge.id,
                    device: DeviceDescriptor {
                        id: random_id(),
                        name: "Persistent TURN browser fixture".into(),
                        platform: "web".into(),
                        public_key: URL_SAFE_NO_PAD.encode(browser.public_key()),
                        capabilities: vec!["controller".into(), "vp8".into()],
                        path_mode: "direct_preferred".into(),
                    },
                    signature: String::new(),
                };
                registration.signature =
                    URL_SAFE_NO_PAD.encode(browser.sign_action(&f.s.registration_transcript(
                        &f.admin,
                        &registration,
                        1000,
                    )?)?);
                let id = registration.device.id.clone();
                f.s.register_device(&f.admin, registration, 1000)?;
                id
            } else {
                let challenge = f.s.enrollment_challenge(&f.admin, 1001)?;
                let mut registration = BrowserEndpointRegistration {
                    challenge_id: challenge.id,
                    device: DeviceDescriptor {
                        id: random_id(),
                        name: "TURN browser fixture".into(),
                        platform: "web".into(),
                        public_key: URL_SAFE_NO_PAD.encode(browser.public_key()),
                        capabilities: vec!["controller".into(), "vp8".into()],
                        path_mode: "direct_preferred".into(),
                    },
                    signature: String::new(),
                };
                registration.signature = URL_SAFE_NO_PAD.encode(browser.sign_action(
                    &f.s.browser_endpoint_transcript(&f.admin, &registration, 1001)?,
                )?);
                f.s.register_browser_endpoint(&f.admin, registration, 1001)?
                    .device_id
            };
        f.permit = approve(
            &mut f.s,
            &f.admin,
            &f.host,
            &f.h,
            &endpoint_id,
            &f.permit.host_device_id,
            1001,
        )?;
        f.c = browser;
        f.s.set_turn_endpoints(
            &f.admin,
            &f.node_id,
            TurnEndpointsUpdate {
                expected_revision: 0,
                config: TurnEndpointConfig {
                    realm: "nestlink-test".into(),
                    endpoints: vec!["turns:turn.example.test:443?transport=tcp".into()],
                    allow_loopback: false,
                },
            },
            NOW,
        )?;
        f.at(NOW);
        Ok(f)
    }
    fn turn_request(&self, host: bool, id: &str, generation: u64) -> Result<TurnCredentialRequest> {
        let (p, key, device) = if host {
            (&self.host, &self.h, &self.permit.host_device_id)
        } else {
            (&self.admin, &self.c, &self.permit.controller_device_id)
        };
        let mut request = TurnCredentialRequest {
            allocation_id: id.into(),
            device_id: device.clone(),
            network_generation: generation,
            signature: String::new(),
        };
        request.signature = URL_SAFE_NO_PAD.encode(key.sign_action(
            &credential_request_transcript(&self.permit, &p.account_id, &request)?,
        )?);
        Ok(request)
    }
    fn turn_query(&self, sequence: u64, now: u64) -> Result<SignedTurnResourceQuery> {
        let (generation,policy,lease):(u64,u64,u64)=self.s.connection.query_row("SELECT runtime_generation,lease_policy_revision,lease_sequence FROM data_nodes WHERE id=?1",[&self.node_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        Ok(self
            .node
            .sign_turn_resource_query(&TurnResourceQueryClaims {
                schema_version: SCHEMA_VERSION,
                deployment_id: self.s.deployment_id()?,
                security_epoch: self.s.security_epoch()?,
                node_id: self.node_id.clone(),
                runtime_id: self.node_runtime.clone(),
                runtime_generation: generation,
                policy_revision: policy,
                lease_sequence: lease,
                request_id: random_id(),
                request_sequence: sequence,
                issued_at_unix_ms: now,
                expires_at_unix_ms: now + 1000,
            })?)
    }
}

#[test]
fn permanent_browser_turn_credentials_are_permit_bounded_and_revocable() -> Result {
    let mut f = Fixture::permanent_browser_turn()?;
    let vault = VaultKey::from_bytes([7; 32]);
    assert_eq!(
        f.s.device_expiration_ms(&f.permit.controller_device_id)?,
        None
    );
    let request = f.turn_request(false, &random_id(), 1)?;
    let credentials = f.s.turn_credentials(
        &f.lifecycle,
        &vault,
        &f.admin,
        &f.permit.session_id,
        &request,
        NOW,
    )?;
    assert!(credentials.expires_at_unix_ms <= f.permit.expires_at_unix_ms);
    assert!(credentials.expires_at_unix_ms > NOW);
    f.s.revoke_device_as(
        &f.admin,
        &random_id(),
        &f.permit.controller_device_id,
        NOW / 1000,
    )?;
    assert!(
        f.s.turn_credentials(
            &f.lifecycle,
            &vault,
            &f.admin,
            &f.permit.session_id,
            &request,
            NOW,
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn turn_is_browser_only_endpoint_signed_and_uses_shared_persistent_capacity() -> Result {
    let mut native = Fixture::new(false, 8)?;
    let vault = VaultKey::from_bytes([7; 32]);
    let request = native.turn_request(false, &random_id(), 1)?;
    assert!(
        native
            .s
            .turn_credentials(
                &native.lifecycle,
                &vault,
                &native.admin,
                &native.permit.session_id,
                &request,
                NOW
            )
            .is_err()
    );
    let mut f = Fixture::browser_turn()?;
    f.quota(1, 2)?;
    let request = f.turn_request(false, &random_id(), 1)?;
    let mut bad = request.clone();
    bad.signature = URL_SAFE_NO_PAD.encode([0; 64]);
    assert!(
        f.s.turn_credentials(
            &f.lifecycle,
            &vault,
            &f.admin,
            &f.permit.session_id,
            &bad,
            NOW
        )
        .is_err()
    );
    assert!(
        f.s.turn_credentials(
            &f.lifecycle,
            &vault,
            &f.host,
            &f.permit.session_id,
            &request,
            NOW
        )
        .is_err()
    );
    let credentials = f.s.turn_credentials(
        &f.lifecycle,
        &vault,
        &f.admin,
        &f.permit.session_id,
        &request,
        NOW,
    )?;
    assert_eq!(
        credentials.endpoints,
        vec!["turns:turn.example.test:443?transport=tcp"]
    );
    let retry = f.s.turn_credentials(
        &f.lifecycle,
        &vault,
        &f.admin,
        &f.permit.session_id,
        &request,
        NOW,
    )?;
    assert_eq!(credentials, retry);
    let stored: String = f.s.connection.query_row(
        "SELECT claims_json FROM turn_grants WHERE id=?1",
        [&request.allocation_id],
        |r| r.get(0),
    )?;
    assert!(!stored.contains(&credentials.password));
    assert_eq!(
        serde_json::from_str::<TurnGrantClaims>(&stored)?
            .auth_key
            .len(),
        0
    );
    assert_eq!(f.usage(NOW)?.turn_allocations, 1);
    assert_eq!(f.usage(NOW)?.held_endpoint_slots, 1);
    assert!(f.combined(false, NOW).is_err());
    let peer = f.turn_request(true, &random_id(), 1)?;
    assert!(
        f.s.turn_credentials(
            &f.lifecycle,
            &vault,
            &f.host,
            &f.permit.session_id,
            &peer,
            NOW
        )
        .is_err()
    );
    f.s.revoke_remote(&f.host, &f.permit.session_id)?;
    assert!(
        f.s.turn_credentials(
            &f.lifecycle,
            &vault,
            &f.admin,
            &f.permit.session_id,
            &request,
            NOW
        )
        .is_err()
    );
    assert_eq!(f.usage(NOW)?.held_allocations, 1);
    let q = f.turn_query(1, NOW)?;
    assert!(
        f.s.turn_resource_snapshot(&f.lifecycle, &vault, &q, NOW)?
            .grants
            .is_empty()
    );
    Ok(())
}
#[test]
fn turn_snapshot_is_peerless_until_both_signatures_and_does_not_replay_or_revive() -> Result {
    let mut f = Fixture::browser_turn()?;
    let vault = VaultKey::from_bytes([7; 32]);
    let c_request = f.turn_request(false, &random_id(), 1)?;
    let h_request = f.turn_request(true, &random_id(), 1)?;
    let c = f.s.turn_credentials(
        &f.lifecycle,
        &vault,
        &f.admin,
        &f.permit.session_id,
        &c_request,
        NOW,
    )?;
    let h = f.s.turn_credentials(
        &f.lifecycle,
        &vault,
        &f.host,
        &f.permit.session_id,
        &h_request,
        NOW,
    )?;
    assert_ne!(c.password, h.password);
    assert_ne!(c.username, h.username);
    let query = f.turn_query(1, NOW)?;
    let initial =
        f.s.turn_resource_snapshot(&f.lifecycle, &vault, &query, NOW)?;
    assert_eq!(initial.grants.len(), 2);
    assert!(initial.peer_bindings.is_empty());
    let signer = nestlink_identity::nodes::NodePolicySigner::from_master_seed(&[13; 32])?;
    assert_eq!(
        verify_turn_resource_snapshot(
            &signer.sign_turn_resource_snapshot(&initial)?,
            &signer.public_key(),
            &query
        )?,
        initial
    );
    assert!(
        f.s.turn_resource_snapshot(&f.lifecycle, &vault, &query, NOW)
            .is_err()
    );
    let binding = TurnPeerBindingClaims {
        schema_version: SCHEMA_VERSION,
        deployment_id: f.permit.deployment_id.clone(),
        security_epoch: f.permit.security_epoch,
        session_id: f.permit.session_id.clone(),
        temporary_identity: f.permit.controller_device_id.clone(),
        purpose: TurnPurpose::BrowserWebRtc as i32,
        controller_allocation_id: c.allocation_id.clone(),
        host_allocation_id: h.allocation_id.clone(),
        controller_device_id: f.permit.controller_device_id.clone(),
        host_device_id: f.permit.host_device_id.clone(),
        controller_key_sha256: f.permit.controller_key_sha256.clone(),
        host_key_sha256: f.permit.host_key_sha256.clone(),
        controller_network_generation: 1,
        host_network_generation: 1,
        connection_generation: f.permit.connection_generation,
        lease_sequence: f.permit.lease_sequence,
        permit_sha256: digest(&f.permit.encode_to_vec()).to_vec(),
        controller_candidates: vec!["8.8.8.8:40000".into()],
        host_candidates: vec!["1.1.1.1:50000".into()],
        issued_at_unix_ms: NOW,
        expires_at_unix_ms: c.expires_at_unix_ms.min(h.expires_at_unix_ms),
    };
    let host_proof = TurnPeerSubmission {
        device_id: h.device_id.clone(),
        claims: binding.encode_to_vec(),
        signature: f.h.sign_turn_peer_binding(&binding)?,
    };
    f.s.submit_turn_peers(&f.host, &f.permit.session_id, &host_proof, NOW)?;
    let query = f.turn_query(2, NOW)?;
    assert!(
        f.s.turn_resource_snapshot(&f.lifecycle, &vault, &query, NOW)?
            .peer_bindings
            .is_empty()
    );
    let controller_proof = TurnPeerSubmission {
        device_id: c.device_id.clone(),
        claims: binding.encode_to_vec(),
        signature: f.c.sign_turn_peer_binding(&binding)?,
    };
    f.s.submit_turn_peers(&f.admin, &f.permit.session_id, &controller_proof, NOW)?;
    let query = f.turn_query(3, NOW)?;
    let active =
        f.s.turn_resource_snapshot(&f.lifecycle, &vault, &query, NOW)?;
    assert_eq!(active.peer_bindings.len(), 1);
    let mut altered = binding.clone();
    altered.host_candidates = vec!["9.9.9.9:50000".into()];
    let altered = TurnPeerSubmission {
        device_id: h.device_id.clone(),
        claims: altered.encode_to_vec(),
        signature: f.h.sign_turn_peer_binding(&altered)?,
    };
    assert!(
        f.s.submit_turn_peers(&f.host, &f.permit.session_id, &altered, NOW)
            .is_err()
    );
    let replacement = f.turn_request(false, &random_id(), 2)?;
    f.s.turn_credentials(
        &f.lifecycle,
        &vault,
        &f.admin,
        &f.permit.session_id,
        &replacement,
        NOW,
    )?;
    assert!(
        f.s.turn_credentials(
            &f.lifecycle,
            &vault,
            &f.admin,
            &f.permit.session_id,
            &c_request,
            NOW
        )
        .is_err()
    );
    let state =
        f.s.turn_binding_state(&f.admin, &f.permit.session_id, NOW)?;
    assert_eq!(
        state.controller_allocation_id.as_deref(),
        Some(replacement.allocation_id.as_str())
    );
    assert_eq!(
        state.host_allocation_id.as_deref(),
        Some(h.allocation_id.as_str())
    );
    assert!(state.binding.is_none());
    let query = f.turn_query(4, NOW)?;
    let replaced =
        f.s.turn_resource_snapshot(&f.lifecycle, &vault, &query, NOW)?;
    assert!(
        replaced
            .grants
            .iter()
            .all(|g| g.allocation_id != c.allocation_id)
    );
    // A completed binding cannot be attached to a replacement allocation.
    assert!(replaced.peer_bindings.is_empty());
    Ok(())
}
