use super::*;
use nestlink_identity::{
    InstallationIdentity, PermitSigner, network::*, relay::session_binding, verify_permit,
};
use nestlink_protocol::{
    NodeNetworkRelayResource,
    api::{
        NetworkGrantView, NetworkRemotePathView, NetworkRemoteRelayView, NodeEndpoints,
        NodeEndpointsView,
    },
    network::*,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn resource() -> TestResult<(NodeNetworkRelayResource, InstallationIdentity)> {
    let root = PermitSigner::from_seed([1; 32]);
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../tests/vectors/session-permit-v1.json"
    ))?;
    let hex = vector["envelope_hex"]
        .as_str()
        .ok_or("permit vector missing")?;
    let envelope = (0..hex.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&hex[n..n + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    let mut business = verify_permit(&envelope, &root.public_key())?
        .claims()
        .clone();
    let first = InstallationIdentity::generate();
    let second = InstallationIdentity::generate();
    let mut allocation = grant();
    allocation.bytes_per_second = 10_000;
    allocation.bytes_per_allocation = 10_000;
    business.deployment_id = allocation.deployment_id.clone();
    business.security_epoch = allocation.security_epoch;
    business.session_id = allocation.session_id.clone();
    business.account_id = allocation.controller_account_id.clone();
    business.controller_device_id = allocation.controller_device_id.clone();
    business.host_device_id = allocation.host_device_id.clone();
    business.controller_key_sha256 = first.fingerprint().to_vec();
    business.host_key_sha256 = second.fingerprint().to_vec();
    business.policy_revision = allocation.policy_revision;
    business.connection_generation = allocation.connection_generation;
    business.paths = vec![nestlink_protocol::Path::Relay as i32];
    business.issued_at_unix_ms = allocation.issued_at_unix_ms;
    business.expires_at_unix_ms = allocation.expires_at_unix_ms;
    let permit = verify_permit(&root.sign(&business)?.encode_to_vec(), &root.public_key())?;
    allocation.controller_key_sha256 = business.controller_key_sha256.clone();
    allocation.host_key_sha256 = business.host_key_sha256.clone();
    allocation.session_binding_sha256 = session_binding(&business)?.to_vec();
    allocation.transports = vec![RelayTransport::QuicDatagram as i32];
    let authority = NetworkAuthoritySigner::from_master_seed(&[64; 32])?;
    let key = authority.public_key();
    let revoked = std::collections::BTreeSet::new();
    let space = id(20);
    let context = NetworkVerification {
        authority_key: &key,
        deployment_id: &business.deployment_id,
        space_id: &space,
        policy_epoch: 9,
        now_ms: 10000,
        revoked_grant_ids: &revoked,
    };
    let scope = |n| GrantScope {
        schema_version: 1,
        deployment_id: business.deployment_id.clone(),
        space_id: space.clone(),
        grant_id: id(n),
        policy_epoch: 9,
        not_before_ms: business.issued_at_unix_ms,
        expires_at_ms: business.expires_at_unix_ms,
    };
    let mut members = Vec::new();
    let mut credentials = Vec::new();
    for (n, device, identity) in [
        (21, &business.controller_device_id, &first),
        (22, &business.host_device_id, &second),
    ] {
        let signed = authority.sign(&GrantClaims::Membership(MembershipClaims {
            scope: scope(n),
            installation_id: device.clone(),
            public_key: identity.public_key(),
            peer: PeerId(identity.fingerprint()),
            membership_epoch: 1,
            role: SpaceRole::Member,
        }))?;
        members.push(VerifiedMembership::from_grant(
            verify_network_grant(&signed, &context)?,
            &context,
            device,
            &identity.public_key(),
            1,
        )?);
        credentials.push(signed);
    }
    let peers = PeerPair::new(PeerId(first.fingerprint()), PeerId(second.fingerprint()))?;
    let digests = if members[0].peer() == peers.first {
        [members[0].digest(), members[1].digest()]
    } else {
        [members[1].digest(), members[0].digest()]
    };
    let connectivity = authority.sign(&GrantClaims::Connectivity(ConnectivityClaims {
        scope: scope(23),
        peers,
        purpose: Purpose::RemoteControl,
        membership_digests: digests,
        business_grant_digest: permit.digest(),
    }))?;
    let relay = PeerId(allocation.node_key_sha256.as_slice().try_into()?);
    let path = authority.sign(&GrantClaims::Path(PathClaims {
        scope: scope(24),
        peers,
        purpose: Purpose::RemoteControl,
        connectivity_grant_digest: verify_network_grant(&connectivity, &context)?.digest(),
        policy: PathPolicy {
            allow_direct: false,
            relays: vec![relay],
            max_hops: 1,
        },
    }))?;
    let verified = VerifiedNetworkPath::from_grants(
        &context,
        [members.remove(0), members.remove(0)],
        verify_network_grant(&connectivity, &context)?,
        verify_network_grant(&path, &context)?,
        permit.digest(),
    )?;
    let transit = authority.sign(&GrantClaims::Transit(TransitClaims {
        scope: scope(25),
        peers,
        relay,
        previous: peers.first,
        next: peers.second,
        transport_group: verified.transport_group_id(),
        route_id: allocation.allocation_id.clone(),
        remaining_hops: 1,
        byte_limit: allocation.bytes_per_allocation,
    }))?;
    let view = |signed: SignedNetworkGrant| -> TestResult<NetworkGrantView> {
        let claims = GrantClaims::decode_canonical(&signed.claims)?;
        Ok(NetworkGrantView {
            schema_version: 1,
            grant_id: claims.scope().grant_id.clone(),
            claims: URL_SAFE_NO_PAD.encode(signed.claims),
            signature: URL_SAFE_NO_PAD.encode(signed.signature),
        })
    };
    let bundle = NetworkRemoteRelayView {
        allocation_id: allocation.allocation_id.clone(),
        path: NetworkRemotePathView {
            request_id: business.session_id,
            controller_membership: view(credentials.remove(0))?,
            host_membership: view(credentials.remove(0))?,
            connectivity: view(connectivity)?,
            path: view(path)?,
        },
        transit: view(transit)?,
        node: NodeEndpointsView {
            node_id: allocation.node_id.clone(),
            revision: allocation.node_endpoint_revision,
            endpoints: NodeEndpoints {
                quic_uri: Some("quic://127.0.0.1:28744".into()),
                wss_origin: None,
                allow_loopback: true,
            },
        },
    };
    Ok((
        NodeNetworkRelayResource {
            network_schema_version: 1,
            allocation: Some(allocation),
            network_authority_key: key.to_vec(),
            relay_bundle_json: serde_json::to_vec(&bundle)?,
            business_permit: permit.signed_envelope().to_vec(),
        },
        first,
    ))
}

#[test]
fn network_routes_share_pair_counters_and_cannot_reset_reuse_or_mint_legacy_close_receipts()
-> TestResult {
    let (resource, _) = resource()?;
    let claims = resource
        .allocation
        .as_ref()
        .ok_or("allocation missing")?
        .clone();
    let mut signed = snapshot(1, clock(0, 10000), Vec::new());
    signed.allocation_issuer = PermitSigner::from_seed([1; 32]).public_key().to_vec();
    signed.network_routes = vec![resource];
    let mut resources = Resources::default();
    resources.accept(signed.clone(), &lease(), 0, clock(0, 10000))?;
    let (a, _) = resources.reserve(&claims, 0, clock(0, 10000))?;
    let (b, stopped) = resources.reserve(&claims, 1, clock(0, 10000))?;
    assert!(resources.reserve(&claims, 0, clock(0, 10000)).is_err());
    resources.admit(&claims.allocation_id, &a, 6000, clock(0, 10000), || Ok(()))?;
    signed
        .query
        .as_mut()
        .ok_or("query missing")?
        .request_sequence = 2;
    resources.accept(signed.clone(), &lease(), 0, clock(0, 10000))?;
    resources.admit(&claims.allocation_id, &b, 4000, clock(0, 10000), || Ok(()))?;
    assert!(
        resources
            .admit(&claims.allocation_id, &a, 1, clock(0, 10000), || Ok(()))
            .is_err()
    );
    assert!(
        resources
            .accept(signed, &lease(), 0, clock(0, 10000))
            .is_err()
    );
    assert!(resources.close_after_io(&claims.allocation_id, &a, Some(10001), false));
    assert!(*stopped.borrow());
    assert!(resources.close_after_io(&claims.allocation_id, &b, Some(10002), false));
    assert!(resources.pending_closes.is_empty());
    assert!(resources.reserve(&claims, 0, clock(2, 10002)).is_err());
    Ok(())
}

#[test]
fn network_snapshot_rejects_changed_envelopes_authority_versions_and_stops_omitted_routes()
-> TestResult {
    let (resource, identity) = resource()?;
    let root = PermitSigner::from_seed([1; 32]);
    let binding = verify_node_network_resource(&resource, &root.public_key(), 10000)?;
    let claims = resource.allocation.as_ref().ok_or("allocation missing")?;
    let nonce = [7; 32];
    let signature = identity.sign_network_node_admission(
        &claims.allocation_id,
        &binding.digest,
        &claims.controller_device_id,
        &nonce,
    )?;
    verify_network_node_admission(
        &claims.allocation_id,
        &binding.digest,
        &claims.controller_device_id,
        &identity.public_key(),
        &nonce,
        &signature,
    )?;
    assert!(
        verify_network_node_admission(
            &claims.allocation_id,
            &binding.digest,
            &claims.controller_device_id,
            &identity.public_key(),
            &[8; 32],
            &signature
        )
        .is_err()
    );
    let mut snapshot = snapshot(1, clock(0, 10000), Vec::new());
    snapshot.allocation_issuer = root.public_key().to_vec();
    snapshot.network_routes = vec![resource.clone()];
    let mut resources = Resources::default();
    resources.accept(snapshot.clone(), &lease(), 0, clock(0, 10000))?;
    let (_, stopped) = resources.reserve(claims, 0, clock(0, 10000))?;
    let mut changed = snapshot.clone();
    changed.network_routes[0].business_permit[0] ^= 1;
    changed
        .query
        .as_mut()
        .ok_or("query missing")?
        .request_sequence = 2;
    assert!(
        resources
            .accept(changed, &lease(), 0, clock(0, 10000))
            .is_err()
    );
    let mut changed = snapshot.clone();
    changed.network_routes[0].network_schema_version = 2;
    assert!(changed.validate().is_err());
    let mut changed = snapshot.clone();
    changed.network_routes[0].network_authority_key[0] ^= 1;
    assert!(
        verify_node_network_resource(&changed.network_routes[0], &root.public_key(), 10000)
            .is_err()
    );
    snapshot
        .query
        .as_mut()
        .ok_or("query missing")?
        .request_sequence = 2;
    snapshot.network_routes.clear();
    resources.accept(snapshot, &lease(), 0, clock(0, 10000))?;
    assert!(*stopped.borrow());
    Ok(())
}
