//! Real signatures over an original group; mutations cannot become candidates.
use super::*;
use nestlink_protocol::api::{
    NetworkGrantView, NetworkRemoteRouteSetMemberView, NetworkRemoteRouteSetView,
};

fn view(base: &Fixture) -> Result<NetworkRemoteRouteSetView> {
    let signer = NetworkAuthoritySigner::from_master_seed(&[83; 32])?;
    let context = base.context();
    let encode = |claims: &GrantClaims| -> Result<NetworkGrantView> {
        let signed = signer.sign(claims)?;
        Ok(NetworkGrantView {
            schema_version: 1,
            grant_id: claims.scope().grant_id.clone(),
            claims: URL_SAFE_NO_PAD.encode(signed.claims),
            signature: URL_SAFE_NO_PAD.encode(signed.signature),
        })
    };
    let second = InstallationIdentity::generate();
    let mut claims = base.path.claims().clone();
    claims.policy.relays.push(PeerId(second.fingerprint()));
    claims.policy.relays.sort();
    let path_view = encode(&GrantClaims::Path(claims.clone()))?;
    let mut members = Vec::new();
    for (member, device) in [
        (&base.response.path.controller_membership, &base.controller),
        (&base.response.path.host_membership, &base.host),
    ] {
        let grant = verify_network_grant(
            &crate::network_management::decode_network_grant(member)?,
            &context,
        )?;
        members.push(VerifiedMembership::from_grant(
            grant,
            &context,
            &device.device_id,
            &device.identity.public_key(),
            1,
        )?);
    }
    let path = VerifiedNetworkPath::from_grants(
        &context,
        [members.remove(0), members.remove(0)],
        base.connectivity.clone(),
        verify_network_grant(&signer.sign(&GrantClaims::Path(claims))?, &context)?,
        base.permit.digest(),
    )?;
    let mut ids = [random_id(), random_id()];
    ids.sort();
    let GrantClaims::Transit(mut first) = base.transit.claims().clone() else {
        return Err("transit".into());
    };
    first.route_id = ids[0].clone();
    first.transport_group = path.transport_group_id();
    first.byte_limit /= 2;
    let mut second_transit = first.clone();
    second_transit.scope.grant_id = random_id();
    second_transit.route_id = ids[1].clone();
    second_transit.relay = PeerId(second.fingerprint());
    let mut second_node = base.response.node.clone();
    second_node.node_id = random_id();
    let mut path_response = base.response.path.clone();
    path_response.path = path_view;
    Ok(NetworkRemoteRouteSetView {
        set_id: random_id(),
        path: path_response,
        members: [
            NetworkRemoteRouteSetMemberView {
                allocation_id: ids[0].clone(),
                transit: encode(&GrantClaims::Transit(first))?,
                node: base.response.node.clone(),
                available: true,
            },
            NetworkRemoteRouteSetMemberView {
                allocation_id: ids[1].clone(),
                transit: encode(&GrantClaims::Transit(second_transit))?,
                node: second_node,
                available: true,
            },
        ],
    })
}

#[test]
fn original_route_set_readback_preserves_distinct_routes_at_the_same_address_and_gates_availability()
-> Result {
    let f = Fixture::new(true)?;
    let sdk = readback_sdk(&f)?;
    let pin = super::super::PinnedNetworkSpace::new(SPACE.into(), f.issuer)?;
    let response = view(&f)?;
    for (local, peer) in [(&f.controller, &f.host), (&f.host, &f.controller)] {
        let route = sdk.verify_route_set_readback(
            &pin,
            local,
            &f.permit,
            &peer.identity.public_key(),
            &response.set_id,
            response.clone(),
            Instant::now(),
        )?;
        assert!(route.is_current_for(&sdk, local, &f.permit, &peer.identity.public_key()));
        let candidates = route.candidates();
        assert_eq!(
            candidates[0].node().endpoints.quic_uri,
            candidates[1].node().endpoints.quic_uri
        );
        assert_ne!(candidates[0].route_binding(), candidates[1].route_binding());
        assert_ne!(candidates[0].relay(), candidates[1].relay());
        assert!(
            route
                .candidate_for_admission(&sdk, local, &f.permit, &peer.identity.public_key(), 0)
                .is_some()
        );
        assert!(
            route
                .candidate_for_admission(&sdk, local, &f.permit, &peer.identity.public_key(), 2)
                .is_none()
        );
    }
    let mut unavailable = response.clone();
    unavailable.members[0].available = false;
    let route = sdk.verify_route_set_readback(
        &pin,
        &f.controller,
        &f.permit,
        &f.host.identity.public_key(),
        &unavailable.set_id,
        unavailable.clone(),
        Instant::now(),
    )?;
    assert!(
        route
            .candidate_for_admission(
                &sdk,
                &f.controller,
                &f.permit,
                &f.host.identity.public_key(),
                0
            )
            .is_none()
    );
    assert!(
        route
            .candidate_for_admission(
                &sdk,
                &f.controller,
                &f.permit,
                &f.host.identity.public_key(),
                1
            )
            .is_some()
    );
    let other = readback_sdk(&f)?;
    assert!(!route.is_current_for(
        &other,
        &f.controller,
        &f.permit,
        &f.host.identity.public_key()
    ));
    assert!(
        route
            .candidate_for_admission(
                &sdk,
                &f.host,
                &f.permit,
                &f.controller.identity.public_key(),
                1
            )
            .is_none()
    );
    Ok(())
}

#[test]
fn route_set_readback_rejects_crossed_group_transits_retargeted_members_wrong_pins_and_stale_source()
-> Result {
    let f = Fixture::new(true)?;
    let sdk = readback_sdk(&f)?;
    let pin = super::super::PinnedNetworkSpace::new(SPACE.into(), f.issuer)?;
    let response = view(&f)?;
    for fault in 0..8 {
        let mut changed = response.clone();
        match fault {
            0 => changed.members[1].transit = f.response.transit.clone(),
            1 => changed.members[1].transit = changed.members[0].transit.clone(),
            2 => changed.members[0].allocation_id = random_id(),
            3 => changed.members[1].node.node_id = changed.members[0].node.node_id.clone(),
            4 => changed.members.swap(0, 1),
            5 => changed.path.path = f.response.path.path.clone(),
            6 => changed.members[0].transit.signature = "A".repeat(86),
            _ => changed.path.request_id = random_id(),
        }
        assert!(
            sdk.verify_route_set_readback(
                &pin,
                &f.controller,
                &f.permit,
                &f.host.identity.public_key(),
                &response.set_id,
                changed,
                Instant::now()
            )
            .is_err(),
            "fault {fault}"
        );
    }
    for pin in [
        super::super::PinnedNetworkSpace::new(SPACE.into(), [11; 32])?,
        super::super::PinnedNetworkSpace::new(random_id(), f.issuer)?,
    ] {
        assert!(
            sdk.verify_route_set_readback(
                &pin,
                &f.controller,
                &f.permit,
                &f.host.identity.public_key(),
                &response.set_id,
                response.clone(),
                Instant::now()
            )
            .is_err()
        );
    }
    assert!(
        sdk.verify_route_set_readback(
            &pin,
            &f.controller,
            &f.permit,
            &[99; 32],
            &response.set_id,
            response.clone(),
            Instant::now()
        )
        .is_err()
    );
    assert!(
        sdk.verify_route_set_readback(
            &pin,
            &f.controller,
            &f.permit,
            &f.host.identity.public_key(),
            &response.set_id,
            response.clone(),
            Instant::now() - Duration::from_secs(6)
        )
        .is_err()
    );
    Ok(())
}
