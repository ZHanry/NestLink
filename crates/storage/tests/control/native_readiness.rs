use super::*;
use nestlink_protocol::{
    Path,
    api::{NativeIceParameters, NativeRendezvous, SignalPayload, SignalSubmission},
};

#[test]
fn signed_address_free_rendezvous_and_native_ice_wake_only_the_live_authorized_host() -> Result {
    for relay in [true, false] {
        let (mut store, _, _, controller_account, host_account) = fixture()?;
        store.apply_policy(
            1,
            nestlink_policy::NetworkPolicy {
                server_forwarding: nestlink_policy::ServerForwarding::Allow,
                peer_path_mode: nestlink_policy::PeerPathMode::DirectPreferred,
                public_ingress: nestlink_policy::PublicIngress::Disabled,
            },
        )?;
        let controller = InstallationIdentity::generate();
        let host = InstallationIdentity::generate();
        let controller_id = super::native_ice_capabilities::enroll_capabilities(&mut store, &controller_account, &controller, "controller", "windows", !relay)?;
        let host_id = super::native_ice_capabilities::enroll_capabilities(&mut store, &host_account, &host, "host", "windows", !relay)?;
        let request = store.create_remote(
            &controller_account,
            RemoteRequest {
                id: random_id(),
                controller_device_id: controller_id.clone(),
                host_device_id: host_id.clone(),
                permissions: vec![Permission::View as i32],
                path_mode: if relay { "relay_only" } else { "direct_only" }.into(),
            },
            1000,
        )?;
        assert!(store.ready_native_remote(&host_account, &host_id, 1000)?.is_empty());
        let choice = ApprovalChoice {
            approved: true,
            permissions: vec![Permission::View as i32],
            paths: vec![if relay { Path::Relay } else { Path::Direct } as i32],
        };
        let proof = store.approval_transcript(&host_account, &request.id, &choice, 1001)?;
        store.approve_remote(
            &host_account,
            &request.id,
            choice,
            &URL_SAFE_NO_PAD.encode(host.sign_action(&proof)?),
            1001,
        )?;
        let permit = store.initial_permit(&controller_account, &request.id, 1002)?;
        assert!(store.ready_native_remote(&host_account, &host_id, 1002)?.is_empty());
        let payload = SignalPayload {
            connection_generation: permit.connection_generation,
            lease_sequence: permit.lease_sequence,
            network_generation: 1,
            sequence: 1,
            candidates: vec![],
            description: None,
            ice: None,
            rendezvous: relay.then_some(NativeRendezvous::CombinedRelay),
            native_ice: (!relay).then(|| NativeIceParameters {
                version: 1,
                username_fragment: "abcdefgh".into(),
                password: "abcdefghijklmnopqrstuvwx".into(),
                candidate: "1234 1 udp 2130706431 203.0.113.7 45678 typ host".into(),
            }),
        };
        let proof = nestlink_identity::signal_transcript(
            &permit,
            &controller_account.account_id,
            &controller_id,
            &payload,
        )?;
        let submission = SignalSubmission {
            device_id: controller_id.clone(),
            payload,
            signature: URL_SAFE_NO_PAD.encode(controller.sign_action(&proof)?),
        };
        let mut tampered = submission.clone();
        tampered.payload.network_generation += 1;
        assert!(store.submit_signal(&controller_account, &request.id, tampered, 1003).is_err());
        assert!(store.ready_native_remote(&host_account, &host_id, 1003)?.is_empty());
        store.submit_signal(&controller_account, &request.id, submission, 1003)?;
        let ready = store.ready_native_remote(&host_account, &host_id, 1003)?;
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].id, request.id);
        assert_eq!(ready[0].connection_generation, permit.connection_generation);
        assert!(store.ready_native_remote(&controller_account, &host_id, 1003).is_err());
        assert!(store.ready_native_remote(&host_account, &controller_id, 1003).is_err());
        // A wake hint creates neither a new lease nor permission after expiry.
        let expired = permit.expires_at_unix_ms.div_ceil(1000);
        assert!(store.ready_native_remote(&host_account, &host_id, expired)?.is_empty());
        store.revoke_remote(&controller_account, &request.id)?;
        assert!(store.ready_native_remote(&host_account, &host_id, 1004)?.is_empty());
    }
    Ok(())
}
