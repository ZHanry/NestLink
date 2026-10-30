use super::chain::chain_resource_for_index;
use super::*;
use nestlink_protocol::api::NetworkRemoteRelayChainView;

struct RoutesFixture {
    base: CandidateFixture,
    resources: Vec<NodeNetworkRelayResource>,
    bindings: [NodeRemoteChainBinding; 2],
}

impl RoutesFixture {
    fn new() -> TestResult<Self> {
        Self::with_age(0)
    }

    fn with_age(age_ms: u64) -> TestResult<Self> {
        let base = CandidateFixture::with_node_ttl(10_000, 10_000)?;
        let now = sample(base.control.started)?;
        let issued = now
            .unix_ms
            .checked_sub(age_ms)
            .ok_or("fixture time underflow")?;
        let (single, _) = resource_at(issued, base.lease.node_key_sha256.clone())?;
        let (first, _, _, first_binding) =
            chain_resource_for_index(issued, base.lease.node_key_sha256.clone(), 0)?;
        let (second, _, _, second_binding) =
            chain_resource_for_index(issued, base.lease.node_key_sha256.clone(), 1)?;
        let fixture = Self {
            base,
            resources: vec![single, first, second],
            bindings: [first_binding, second_binding],
        };
        fixture.install(3, &fixture.resources)?;
        Ok(fixture)
    }

    fn install(&self, sequence: u64, resources: &[NodeNetworkRelayResource]) -> TestResult {
        let now = sample(self.base.control.started)?;
        let mut value = snapshot(sequence, now, Vec::new());
        value.allocation_issuer = PermitSigner::from_seed([1; 32]).public_key().to_vec();
        value.network_routes = resources.to_vec();
        self.base
            .control
            .state
            .lock()
            .map_err(|_| "runtime lock")?
            .resources
            .accept(value, &self.base.lease, now.monotonic_ms, now)?;
        Ok(())
    }

    fn local_allocation(&self, index: usize) -> TestResult<&RelayAllocationClaims> {
        self.resources[index + 1]
            .allocation
            .as_ref()
            .ok_or_else(|| "allocation missing".into())
    }
}

#[tokio::test]
async fn chain_routes_return_the_original_opposite_grants_and_endpoints_for_both_relay_positions()
-> TestResult {
    let fixture = RoutesFixture::new()?;
    let routes = fixture.base.control.network_chain_routes()?;
    assert_eq!(routes.len(), 2);
    assert!(
        routes
            .windows(2)
            .all(|pair| pair[0].allocation_id < pair[1].allocation_id)
    );
    // The v1 relay in the same verified snapshot must not be exposed as NRD2.
    assert!(
        fixture
            .base
            .control
            .network_chain_route(
                &fixture.resources[0]
                    .allocation
                    .as_ref()
                    .ok_or("single")?
                    .allocation_id
            )
            .is_err()
    );
    for (index, route) in routes.iter().enumerate() {
        let allocation = fixture.local_allocation(index)?;
        let view: NetworkRemoteRelayChainView =
            serde_json::from_slice(&fixture.resources[index + 1].chain_bundle_json)?;
        let remote = index ^ 1;
        assert_eq!(route.binding, fixture.bindings[index]);
        assert_eq!(route.binding.relay, route.binding.chain.relays[index]);
        assert_eq!(route.allocation_id, allocation.allocation_id);
        assert_eq!(route.neighbor_allocation_id, view.transits[remote].grant_id);
        assert_ne!(route.neighbor_allocation_id, route.allocation_id);
        assert_eq!(route.neighbor_node.node_id, view.nodes[remote].node_id);
        assert_eq!(route.neighbor_node.revision, view.nodes[remote].revision);
        assert_eq!(route.neighbor_node.endpoints, view.nodes[remote].endpoints);
        let lookup = fixture
            .base
            .control
            .network_chain_route(&route.allocation_id)?;
        assert_eq!(lookup.binding, route.binding);
        assert_eq!(lookup.neighbor_allocation_id, route.neighbor_allocation_id);
    }
    assert!(fixture.base.control.network_chain_route(&id(80)).is_err());
    assert_eq!(fixture.base.control.counters()?, Counters::default());
    Ok(())
}

#[tokio::test]
async fn omitted_revoked_snapshot_stopped_resources_and_stopped_nodes_cannot_return_old_routes()
-> TestResult {
    let fixture = RoutesFixture::new()?;
    let allocation = fixture.local_allocation(0)?.allocation_id.clone();
    fixture.install(4, &fixture.resources[2..])?;
    assert_eq!(fixture.base.control.network_chain_routes()?.len(), 1);
    assert!(
        fixture
            .base
            .control
            .network_chain_route(&allocation)
            .is_err()
    );
    fixture.install(5, &[])?;
    assert!(fixture.base.control.network_chain_routes()?.is_empty());
    assert!(
        fixture
            .base
            .control
            .network_chain_route(&allocation)
            .is_err()
    );
    fixture.install(6, &fixture.resources)?;
    assert_eq!(fixture.base.control.network_chain_routes()?.len(), 2);
    fixture
        .base
        .control
        .state
        .lock()
        .map_err(|_| "runtime lock")?
        .resources
        .stop();
    assert!(fixture.base.control.network_chain_routes()?.is_empty());
    fixture.base.control.stop();
    assert!(fixture.base.control.network_chain_routes().is_err());
    assert!(
        fixture
            .base
            .control
            .network_chain_route(&allocation)
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn refreshing_snapshots_does_not_extend_the_original_chain_or_entry_expiration() -> TestResult
{
    // All original grants last 10 seconds. Their late receipt leaves only
    // 800ms, shorter than the fresh snapshot's independent 1000ms lifetime.
    let fixture = RoutesFixture::with_age(9200)?;
    let allocation = fixture.local_allocation(0)?.allocation_id.clone();
    let original = fixture.base.control.network_chain_route(&allocation)?;
    let original_deadline = fixture
        .base
        .control
        .state
        .lock()
        .map_err(|_| "runtime lock")?
        .resources
        .snapshot
        .as_ref()
        .ok_or("snapshot")?
        .entries
        .get(&allocation)
        .ok_or("entry")?
        .deadline;
    tokio::time::sleep(Duration::from_millis(100)).await;
    fixture.install(4, &fixture.resources)?;
    let refreshed = fixture.base.control.network_chain_route(&allocation)?;
    assert_eq!(
        refreshed.binding.chain.expires_at_ms,
        original.binding.chain.expires_at_ms
    );
    {
        let state = fixture
            .base
            .control
            .state
            .lock()
            .map_err(|_| "runtime lock")?;
        let snapshot = state.resources.snapshot.as_ref().ok_or("snapshot")?;
        assert_eq!(
            snapshot.entries.get(&allocation).ok_or("entry")?.deadline,
            original_deadline
        );
        assert!(snapshot.deadline > original_deadline);
    }
    let until = fixture.base.control.started + Duration::from_millis(original_deadline + 5);
    tokio::time::sleep_until(until.into()).await;
    assert!(fixture.base.control.current_lease().is_ok());
    // The refreshed snapshot itself remains present, but its original chain
    // grants and their unchanged entry deadline have now expired.
    assert!(
        fixture
            .base
            .control
            .state
            .lock()
            .map_err(|_| "runtime lock")?
            .resources
            .snapshot
            .is_some()
    );
    assert!(fixture.base.control.network_chain_routes()?.is_empty());
    assert!(
        fixture
            .base
            .control
            .network_chain_route(&allocation)
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn terminal_pairs_and_drained_allocation_watermarks_are_not_dialing_authority() -> TestResult
{
    let fixture = RoutesFixture::new()?;
    let allocation = fixture.local_allocation(0)?.clone();
    let now = sample(fixture.base.control.started)?;
    let (first, second) = {
        let mut state = fixture
            .base
            .control
            .state
            .lock()
            .map_err(|_| "runtime lock")?;
        let (first, _) = state.resources.reserve(&allocation, 0, now)?;
        let (second, _) = state.resources.reserve(&allocation, 1, now)?;
        (first, second)
    };
    assert!(
        fixture
            .base
            .control
            .network_chain_route(&allocation.allocation_id)
            .is_ok()
    );
    {
        let mut state = fixture
            .base
            .control
            .state
            .lock()
            .map_err(|_| "runtime lock")?;
        assert!(state.resources.close_after_io(
            &allocation.allocation_id,
            &first,
            Some(now.unix_ms),
            false
        ));
        assert!(
            state
                .resources
                .pairs
                .get(&allocation.allocation_id)
                .is_some_and(|pair| pair.closed)
        );
    }
    assert!(
        fixture
            .base
            .control
            .network_chain_route(&allocation.allocation_id)
            .is_err()
    );
    {
        let mut state = fixture
            .base
            .control
            .state
            .lock()
            .map_err(|_| "runtime lock")?;
        assert!(state.resources.close_after_io(
            &allocation.allocation_id,
            &second,
            Some(now.unix_ms),
            false
        ));
        assert!(
            !state
                .resources
                .pairs
                .contains_key(&allocation.allocation_id)
        );
        assert!(state.resources.seen.contains(&allocation.allocation_id));
    }
    assert!(
        fixture
            .base
            .control
            .network_chain_route(&allocation.allocation_id)
            .is_err()
    );
    assert_eq!(fixture.base.control.network_chain_routes()?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn route_descriptions_must_still_match_the_original_verified_resource_credential()
-> TestResult {
    let fixture = RoutesFixture::new()?;
    {
        let mut state = fixture
            .base
            .control
            .state
            .lock()
            .map_err(|_| "runtime lock")?;
        let snapshot = state.resources.snapshot.as_mut().ok_or("snapshot")?;
        let resource = &mut snapshot.claims.network_routes[1];
        let mut view: NetworkRemoteRelayChainView =
            serde_json::from_slice(&resource.chain_bundle_json)?;
        view.nodes[1].endpoints.quic_uri = Some("quic://127.0.0.1:1".into());
        resource.chain_bundle_json = serde_json::to_vec(&view)?;
    }
    assert!(fixture.base.control.network_chain_routes().is_err());
    Ok(())
}
