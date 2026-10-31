use super::*;
use nestlink_identity::{digest, network::remote_route_binding_digest, reconnection};
use nestlink_protocol::{
    PermitClaims,
    api::{
        NetworkRemoteRelayRequest, NetworkRouteRecoveryChoice, ReconnectionApproval,
        ReconnectionChoice, ReconnectionOffer, ReconnectionSubmission, RelayAllocationRequest,
    },
};
use prost::Message;

fn submission(f: &RouteSetFixture, choice: ReconnectionChoice) -> Result<ReconnectionSubmission> {
    let previous = f
        .base
        .store
        .current_permit(&f.base.controller, &f.base.request, NOW / 1000)?;
    Ok(ReconnectionSubmission {
        controller_signature: URL_SAFE_NO_PAD.encode(f.base.controller_identity.sign_action(
            &reconnection::transcript(&previous, &previous.controller_device_id, &choice)?,
        )?),
        host_signature: URL_SAFE_NO_PAD.encode(f.base.host_identity.sign_action(
            &reconnection::transcript(&previous, &previous.host_device_id, &choice)?,
        )?),
        choice,
    })
}
fn choice(
    f: &mut RouteSetFixture,
    issued: &NetworkRemoteRouteSetBundle,
    previous: &PermitClaims,
) -> Result<ReconnectionChoice> {
    let snapshot = f.base.store.network_policy_snapshot(&f.base.space, NOW)?;
    let connectivity = verify_network_grant(&issued.path.connectivity, &snapshot.verification())?;
    let transit = verify_network_grant(&issued.members[1].transit, &snapshot.verification())?;
    let group = issued.path.verified().transport_group_id();
    Ok(ReconnectionChoice {
        previous_permit_sha256: URL_SAFE_NO_PAD.encode(digest(&previous.encode_to_vec())),
        connection_generation: previous.connection_generation + 1,
        lease_sequence: previous.lease_sequence + 1,
        nonce: URL_SAFE_NO_PAD.encode([91; 32]),
        network_recovery: Some(NetworkRouteRecoveryChoice {
            version: 1,
            capability: reconnection::NETWORK_RECOVERY_CAPABILITY.into(),
            space_id: f.base.space.clone(),
            route_set_id: issued.set_id.clone(),
            path_grant_id: issued.path.verified().claims().scope.grant_id.clone(),
            original_fingerprint: URL_SAFE_NO_PAD.encode(reconnection::route_set_fingerprint(
                &issued.path.path.claims,
                [
                    &issued.members[0].transit.claims,
                    &issued.members[1].transit.claims,
                ],
            )),
            transport_group: URL_SAFE_NO_PAD.encode(group),
            previous_path_epoch: 1,
            target_node_id: f.nodes[1].0.clone(),
            target_route_binding: URL_SAFE_NO_PAD.encode(remote_route_binding_digest(
                group,
                connectivity.digest(),
                transit.digest(),
                digest(&previous.encode_to_vec()),
                previous.connection_generation,
            )),
            expires_at_unix_ms: issued.path.verified().claims().scope.expires_at_ms,
        }),
    })
}
fn reserve_request(
    f: &RouteSetFixture,
    previous: &PermitClaims,
    next: &PermitClaims,
    choice: &ReconnectionChoice,
) -> Result<NetworkRemoteRelayRequest> {
    let recovery = choice.network_recovery.as_ref().ok_or("recovery")?;
    let id = |purpose| reconnection::network_recovery_id(previous, choice, purpose);
    let allocation = id("allocation")?;
    let signature = f.base.controller_identity.sign_action(
        &nestlink_identity::relay::allocation_transcript(
            next,
            &f.base.controller.account_id,
            &next.controller_device_id,
            &allocation,
            &recovery.target_node_id,
        )?,
    )?;
    Ok(NetworkRemoteRelayRequest {
        path: NetworkRemotePathRequest {
            connectivity_grant_id: id("connectivity")?,
            path_grant_id: id("path")?,
            controller_membership_grant_id: f.base.controller_member.clone(),
            host_membership_grant_id: f.base.host_member.clone(),
            expected_policy_epoch: 3,
            expires_at_unix_ms: recovery.expires_at_unix_ms,
        },
        transit_grant_id: id("transit")?,
        allocation: RelayAllocationRequest {
            allocation_id: allocation,
            node_id: recovery.target_node_id.clone(),
            device_id: next.controller_device_id.clone(),
            signature: URL_SAFE_NO_PAD.encode(signature),
        },
    })
}
fn issue(
    f: &mut RouteSetFixture,
    request: NetworkRemoteRelayRequest,
    now: u64,
) -> std::result::Result<NetworkRemoteRelayBundle, StorageError> {
    f.base.store.issue_network_remote_relay(
        &f.lifecycle,
        &f.base.controller,
        &f.base.signer,
        NetworkRemoteRelayIssuance {
            space_id: f.base.space.clone(),
            request_id: f.base.request.clone(),
            request,
        },
        now,
    )
}
#[test]
fn signed_recovery_has_one_target_one_receipt_fresh_ids_and_unreplenished_original_capacity()
-> Result {
    let mut f = RouteSetFixture::new([8, 8])?;
    let request = f.request()?;
    let old_ids = request.members.clone().map(|member| member.allocation_id);
    let issued = f.issue(request)?;
    let previous = f
        .base
        .store
        .current_permit(&f.base.controller, &f.base.request, NOW / 1000)?;
    let choice = choice(&mut f, &issued, &previous)?;
    let body = submission(&f, choice.clone())?;
    let offer = ReconnectionOffer {
        choice: choice.clone(),
        controller_signature: body.controller_signature.clone(),
    };
    assert!(
        f.base
            .store
            .offer_reconnection_at_ms(&f.base.host, &f.base.request, offer.clone(), NOW + 100)
            .is_err()
    );
    f.base.store.offer_reconnection_at_ms(
        &f.base.controller,
        &f.base.request,
        offer.clone(),
        NOW + 100,
    )?;
    f.base
        .store
        .offer_reconnection_at_ms(&f.base.controller, &f.base.request, offer, NOW + 110)?;
    let mut other = choice.clone();
    other.nonce = URL_SAFE_NO_PAD.encode([92; 32]);
    let other = submission(&f, other)?;
    assert!(matches!(
        f.base.store.offer_reconnection_at_ms(
            &f.base.controller,
            &f.base.request,
            ReconnectionOffer {
                choice: other.choice,
                controller_signature: other.controller_signature
            },
            NOW + 120
        ),
        Err(StorageError::Conflict)
    ));
    let approve = ReconnectionApproval {
        choice: choice.clone(),
        host_signature: body.host_signature.clone(),
    };
    f.base.store.approve_reconnection_at_ms(
        &f.base.host,
        &f.base.request,
        approve.clone(),
        NOW + 130,
    )?;
    f.base
        .store
        .approve_reconnection_at_ms(&f.base.host, &f.base.request, approve, NOW + 140)?;
    let next = f
        .base
        .store
        .reconnect_permit_at_ms(&f.base.controller, &f.base.request, body.clone(), NOW + 150)?
        .next;
    assert_eq!(
        f.base
            .store
            .reconnect_permit_at_ms(&f.base.controller, &f.base.request, body.clone(), NOW + 160)?
            .next,
        next
    );
    assert_eq!(
        f.base
            .store
            .reconnection_state_at_ms(&f.base.host, &f.base.request, NOW + 170)?
            .1
            .ok_or("receipt")?
            .submission,
        body
    );
    assert_eq!(next.expires_at_unix_ms, previous.expires_at_unix_ms);
    assert_eq!(next.permissions, previous.permissions);
    assert_eq!(f.held()?, 2);
    let request = reserve_request(&f, &previous, &next, &choice)?;
    assert!(!old_ids.contains(&request.allocation.allocation_id));
    for variant in 0..3 {
        let mut invalid = request.clone();
        match variant {
            0 => invalid.allocation.node_id = f.nodes[0].0.clone(),
            1 => invalid.path.expires_at_unix_ms += 1,
            _ => invalid.allocation.allocation_id = old_ids[1].clone(),
        }
        assert!(issue(&mut f, invalid, NOW + 180).is_err());
        assert_eq!(f.held()?, 2);
    }
    let fresh = issue(&mut f, request.clone(), NOW + 190)?;
    assert_eq!(f.held()?, 3);
    assert!(matches!(
        issue(&mut f, request, NOW + 200),
        Err(StorageError::Conflict)
    ));
    assert_eq!(f.held()?, 3);
    let read = f.base.store.network_remote_relay(
        &f.lifecycle,
        &f.base.host,
        &f.base.space,
        &fresh.allocation_id,
        NOW + 210,
    )?;
    assert_eq!(read.transit.claims, fresh.transit.claims);
    assert_eq!(read.path.path.claims, fresh.path.path.claims);
    assert_eq!(
        read.path.verified().claims().scope.expires_at_ms,
        issued.path.verified().claims().scope.expires_at_ms
    );
    // Explicit original-group revocation reaches the new route through its
    // retained parent, including node readbacks and lost-response receipts.
    f.base.store.revoke_network_remote_route_set(
        &f.base.host,
        &f.base.space,
        &issued.set_id,
        NOW + 220,
    )?;
    assert!(
        f.base
            .store
            .reconnect_permit_at_ms(&f.base.controller, &f.base.request, body, NOW + 230)
            .is_err()
    );
    assert!(
        f.base
            .store
            .network_remote_relay(
                &f.lifecycle,
                &f.base.host,
                &f.base.space,
                &fresh.allocation_id,
                NOW + 240
            )
            .is_err()
    );
    assert_eq!(f.held()?, 3);
    Ok(())
}
#[test]
fn forged_context_changed_target_policy_and_expiry_never_gain_a_successor() -> Result {
    for variant in 0..7 {
        let mut f = RouteSetFixture::new([8, 8])?;
        let request = f.request()?;
        let issued = f.issue(request)?;
        let previous =
            f.base
                .store
                .current_permit(&f.base.controller, &f.base.request, NOW / 1000)?;
        let mut choice = choice(&mut f, &issued, &previous)?;
        let recovery = choice.network_recovery.as_mut().ok_or("recovery")?;
        match variant {
            0 => recovery.original_fingerprint = URL_SAFE_NO_PAD.encode([0; 32]),
            1 => recovery.target_route_binding = URL_SAFE_NO_PAD.encode([0; 32]),
            2 => recovery.transport_group = URL_SAFE_NO_PAD.encode([0; 32]),
            3 => recovery.space_id = random_id(),
            4 => recovery.expires_at_unix_ms += 1,
            5 => {
                f.base.store.set_node_endpoints(
                    &f.base.controller,
                    &f.nodes[1].0,
                    NodeEndpointsUpdate {
                        expected_revision: 1,
                        endpoints: NodeEndpoints {
                            quic_uri: Some("quic://127.0.0.1:33000".into()),
                            allow_loopback: true,
                            ..NodeEndpoints::default()
                        },
                    },
                    NOW,
                )?;
            }
            _ => {}
        }
        let body = submission(&f, choice)?;
        let now = if variant == 6 { NOW + 2000 } else { NOW + 100 };
        assert!(
            f.base
                .store
                .reconnect_permit_at_ms(&f.base.controller, &f.base.request, body, now)
                .is_err()
        );
        assert_eq!(
            f.base
                .store
                .current_permit(&f.base.controller, &f.base.request, NOW / 1000)?,
            previous
        );
        assert_eq!(f.held()?, 2);
    }
    Ok(())
}
