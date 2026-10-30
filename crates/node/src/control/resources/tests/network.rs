use super::*;
mod chain;
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

#[test]
fn identical_live_network_chain_reuse_requires_fresh_snapshots_and_keeps_original_deadlines()
-> TestResult {
    let (resource, _) = resource()?;
    let claims = resource
        .allocation
        .as_ref()
        .ok_or("allocation missing")?
        .clone();
    let root = PermitSigner::from_seed([1; 32]);
    let mut resources = Resources::default();
    let make_snapshot = |sequence, offset| {
        let mut value = snapshot(sequence, clock(offset, 10000 + offset), Vec::new());
        value.allocation_issuer = root.public_key().to_vec();
        value.network_routes = vec![resource.clone()];
        value
    };
    resources.accept(make_snapshot(1, 0), &lease(), 0, clock(0, 10000))?;
    let original_deadline = resources
        .snapshot
        .as_ref()
        .ok_or("snapshot missing")?
        .entries
        .get(&claims.allocation_id)
        .ok_or("entry missing")?
        .deadline;
    let (_, stopped) = resources.reserve(&claims, 0, clock(0, 10000))?;
    for sequence in 2..=18 {
        let offset = (sequence - 1) * 250;
        resources.accept(
            make_snapshot(sequence, offset),
            &lease(),
            offset,
            clock(offset, 10000 + offset),
        )?;
        assert!(!*stopped.borrow());
        assert_eq!(resources.network_chain_verifications, 1);
        assert_eq!(
            resources
                .snapshot
                .as_ref()
                .ok_or("snapshot missing")?
                .entries
                .get(&claims.allocation_id)
                .ok_or("entry missing")?
                .deadline,
            original_deadline
        );
    }
    let mut changed = make_snapshot(19, 4500);
    changed.network_routes[0].business_permit[0] ^= 1;
    assert!(
        resources
            .accept(changed, &lease(), 4500, clock(4500, 14500))
            .is_err()
    );
    assert_eq!(resources.network_chain_verifications, 2);
    let mut changed = make_snapshot(19, 4500);
    changed.allocation_issuer[0] ^= 1;
    assert!(
        resources
            .accept(changed, &lease(), 4500, clock(4500, 14500))
            .is_err()
    );
    assert_eq!(resources.network_chain_verifications, 3);
    let mut omitted = make_snapshot(19, 4500);
    omitted.network_routes.clear();
    resources.accept(omitted, &lease(), 4500, clock(4500, 14500))?;
    assert!(*stopped.borrow());
    assert!(resources.reserve(&claims, 1, clock(4500, 14500)).is_err());

    let mut expired = Resources::default();
    expired.accept(make_snapshot(1, 0), &lease(), 0, clock(0, 10000))?;
    expired.expire(clock(1000, 11000));
    assert!(expired.snapshot.is_none());
    expired.accept(make_snapshot(2, 1000), &lease(), 1000, clock(1000, 11000))?;
    assert_eq!(expired.network_chain_verifications, 2);
    expired.stop();
    assert!(expired.snapshot.is_none());
    expired.accept(make_snapshot(3, 1250), &lease(), 1250, clock(1250, 11250))?;
    assert_eq!(expired.network_chain_verifications, 3);
    assert!(
        expired
            .accept(
                make_snapshot(4, 10000),
                &lease(),
                10000,
                clock(10000, 20000)
            )
            .is_err()
    );
    Ok(())
}

fn resource() -> TestResult<(NodeNetworkRelayResource, InstallationIdentity)> {
    resource_at(10000, vec![1; 32])
}
fn resource_at(
    issued: u64,
    node_key_sha256: Vec<u8>,
) -> TestResult<(NodeNetworkRelayResource, InstallationIdentity)> {
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
    allocation.node_key_sha256 = node_key_sha256;
    allocation.issued_at_unix_ms = issued;
    allocation.expires_at_unix_ms = issued + 10000;
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
        now_ms: issued,
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
            chain_bundle_json: Vec::new(),
            network_schema_version: 1,
            allocation: Some(allocation),
            network_authority_key: key.to_vec(),
            relay_bundle_json: serde_json::to_vec(&bundle)?,
            business_permit: permit.signed_envelope().to_vec(),
        },
        first,
    ))
}

struct NetworkCandidateFixture {
    base: CandidateFixture,
    resource: NodeNetworkRelayResource,
    binding: RemoteRouteBinding,
}
impl NetworkCandidateFixture {
    fn new(node_ttl: u64) -> TestResult<Self> {
        let mut base = CandidateFixture::with_node_ttl(10000, node_ttl)?;
        let now = sample(base.control.started)?;
        let (resource, endpoint) = resource_at(now.unix_ms, base.lease.node_key_sha256.clone())?;
        let binding = verify_node_network_resource(
            &resource,
            &PermitSigner::from_seed([1; 32]).public_key(),
            now.unix_ms,
        )?;
        base.claims = resource
            .allocation
            .as_ref()
            .ok_or("allocation missing")?
            .clone();
        base.endpoint = endpoint;
        let fixture = Self {
            base,
            resource,
            binding,
        };
        {
            let mut runtime = fixture
                .base
                .control
                .state
                .lock()
                .map_err(|_| Error::Control)?;
            runtime.resources.accept(
                fixture.snapshot(3, now, true),
                &fixture.base.lease,
                now.monotonic_ms,
                now,
            )?;
        }
        Ok(fixture)
    }
    fn snapshot(
        &self,
        sequence: u64,
        now: ClockSample,
        included: bool,
    ) -> NodeResourceSnapshotClaims {
        let mut value = snapshot(sequence, now, Vec::new());
        value.allocation_issuer = PermitSigner::from_seed([1; 32]).public_key().to_vec();
        if included {
            value.network_routes.push(self.resource.clone());
        }
        value
    }
    fn prepare(&self) -> TestResult<RelayEndpointCandidate> {
        let nonce = [19; 32];
        let f = &self.base;
        Ok(f.control.prepare_network_relay_endpoint(
            &f.claims.allocation_id,
            &self.binding.digest,
            &f.endpoint.fingerprint(),
            RelayEndpointProof {
                device_id: &f.claims.controller_device_id,
                public_key: &f.endpoint.public_key(),
                transport: RelayTransport::QuicDatagram,
                signature: &f.endpoint.sign_network_node_admission(
                    &f.claims.allocation_id,
                    &self.binding.digest,
                    &f.claims.controller_device_id,
                    &nonce,
                )?,
            },
            &nonce,
        )?)
    }
}

#[tokio::test]
async fn a_pending_network_candidate_survives_continuous_fresh_snapshots_until_commit() -> TestResult
{
    let f = NetworkCandidateFixture::new(10000)?;
    let candidate = f.prepare()?;
    let prepared = sample(f.base.control.started)?;
    let original_snapshot_deadline = f
        .base
        .control
        .state
        .lock()
        .map_err(|_| Error::Control)?
        .resources
        .snapshot
        .as_ref()
        .ok_or("snapshot missing")?
        .deadline;
    for sequence in 4..=9 {
        let offset = (sequence - 3) * 250;
        let now = clock(prepared.monotonic_ms + offset, prepared.unix_ms + offset);
        let mut runtime = f.base.control.state.lock().map_err(|_| Error::Control)?;
        runtime.resources.accept(
            f.snapshot(sequence, now, true),
            &f.base.lease,
            now.monotonic_ms,
            now,
        )?;
        assert!(candidate.check_at(&mut runtime, now)? > now.monotonic_ms);
    }
    let now = clock(prepared.monotonic_ms + 1500, prepared.unix_ms + 1500);
    assert!(now.monotonic_ms > original_snapshot_deadline);
    assert_eq!(f.base.control.counters()?, Counters::default());
    let reservation = candidate.reserve_at(Some(now))?;
    assert_eq!(f.base.control.counters()?.opened_connections, 1);
    drop(reservation);
    Ok(())
}

#[tokio::test]
async fn a_pending_network_candidate_cannot_revive_after_omission_expiry_or_resource_stop()
-> TestResult {
    for interruption in 0..3 {
        let f = NetworkCandidateFixture::new(10000)?;
        let candidate = f.prepare()?;
        let prepared = sample(f.base.control.started)?;
        let offset = if interruption == 1 { 1000 } else { 250 };
        let now = clock(prepared.monotonic_ms + offset, prepared.unix_ms + offset);
        {
            let mut runtime = f.base.control.state.lock().map_err(|_| Error::Control)?;
            match interruption {
                0 => runtime.resources.accept(
                    f.snapshot(4, now, false),
                    &f.base.lease,
                    now.monotonic_ms,
                    now,
                )?,
                1 => runtime.resources.expire(now),
                _ => runtime.resources.stop(),
            }
            runtime.resources.accept(
                f.snapshot(5, now, true),
                &f.base.lease,
                now.monotonic_ms,
                now,
            )?;
            runtime.resources.inspect(&f.base.claims, 0, now)?;
            assert!(
                candidate.check_at(&mut runtime, now).is_err(),
                "interruption {interruption}"
            );
        }
        assert!(candidate.reserve_at(Some(now)).is_err());
        assert_eq!(f.base.control.counters()?, Counters::default());
    }
    Ok(())
}

#[tokio::test]
async fn a_prepared_network_candidate_keeps_the_original_node_authorization_cutoff() -> TestResult {
    let f = NetworkCandidateFixture::new(3000)?;
    let candidate = f.prepare()?;
    let prepared = sample(f.base.control.started)?;
    let lease = f
        .base
        .renew_node(clock(prepared.monotonic_ms + 500, prepared.unix_ms + 500))?;
    for sequence in 4..=10 {
        let offset = (sequence - 3) * 500;
        let now = clock(prepared.monotonic_ms + offset, prepared.unix_ms + offset);
        let mut runtime = f.base.control.state.lock().map_err(|_| Error::Control)?;
        runtime.resources.accept(
            f.snapshot(sequence, now, true),
            &lease,
            now.monotonic_ms,
            now,
        )?;
    }
    let now = clock(prepared.monotonic_ms + 3500, prepared.unix_ms + 3500);
    {
        let mut runtime = f.base.control.state.lock().map_err(|_| Error::Control)?;
        runtime
            .gate
            .authorize_forwarding(NodeRole::NodeRelay, false, now)?;
        runtime.resources.inspect(&f.base.claims, 0, now)?;
    }
    assert!(candidate.reserve_at(Some(now)).is_err());
    assert_eq!(f.base.control.counters()?, Counters::default());
    Ok(())
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
