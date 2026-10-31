use super::*;

impl ChainFixture {
    fn refresh(&mut self, index: usize, sequence: u64, now: u64, ttl: u64, up: bool) -> Result {
        let signed = self.base.store.topology_publisher(
            &self.base.controller,
            &self.base.space,
            &self.nodes[index].0,
            now,
        )?;
        let snapshot = self
            .base
            .store
            .network_policy_snapshot(&self.base.space, now)?;
        let (id, identity, incarnation) = &self.nodes[index];
        let publisher = verify_topology_publisher(
            &signed,
            &snapshot.verification(),
            id,
            &identity.public_key(),
            incarnation,
            &[],
        )?;
        let report = identity.sign_topology_report(&TopologyReport {
            schema_version: 1,
            deployment_id: self.base.store.deployment_id()?,
            space_id: self.base.space.clone(),
            policy_epoch: 3,
            node_id: id.clone(),
            peer: PeerId::from_public_key(&identity.public_key()),
            publisher_digest: publisher.digest(),
            incarnation: incarnation.clone(),
            sequence,
            not_before_ms: now,
            expires_at_ms: now + ttl,
            neighbors: vec![TopologyNeighbor {
                local: PeerId::from_public_key(&identity.public_key()),
                remote: PeerId::from_public_key(&self.nodes[1 - index].1.public_key()),
                local_endpoint_revision: 1,
                remote_endpoint_revision: 1,
                up,
            }],
            prefixes: Vec::new(),
        })?;
        let ad = self.base.store.accept_topology_report(
            &self.base.signer,
            &self.base.space,
            id,
            &report,
            now,
        )?;
        self.digests[index] = verify_topology_advertisement(
            &ad,
            &publisher,
            &snapshot.verification(),
            incarnation,
            0,
        )?
        .digest();
        Ok(())
    }

    fn issue_at(
        &mut self,
        request: NetworkRemoteRelayChainRequest,
        now: u64,
    ) -> std::result::Result<NetworkRemoteRelayChainBundle, StorageError> {
        self.base.store.issue_network_remote_chain(
            &self.lifecycle,
            &self.base.controller,
            &self.base.signer,
            NetworkRemoteRelayChainIssuance {
                space_id: self.base.space.clone(),
                request_id: self.base.request.clone(),
                request,
            },
            now,
        )
    }

    fn read_at(
        &mut self,
        route: &str,
        now: u64,
    ) -> std::result::Result<NetworkRemoteRelayChainBundle, StorageError> {
        self.base.store.network_remote_chain(
            &self.lifecycle,
            &self.base.host,
            &self.base.space,
            route,
            now,
        )
    }

    fn assert_retired_with_original_holds(&mut self, route: &str, deadline: u64) -> Result {
        edit_snapshot(&mut self.base, |db| {
            assert_eq!(db.query_row(
                "SELECT count(*) FROM network_remote_chain_hops WHERE route_id=?1 AND closed=1 AND promised_until=?2",
                rusqlite::params![route,deadline+1000], |r|r.get::<_,u64>(0),
            )?, 2);
            assert!(db.query_row(
                "SELECT p.revoked FROM network_remote_paths p JOIN network_remote_chains c ON c.space_id=p.space_id AND c.path_grant_id=p.path_grant_id WHERE c.route_id=?1",
                [route], |r|r.get::<_,bool>(0),
            )?);
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM all_relay_capacity WHERE id=?1 AND promised_until=?2",
                    rusqlite::params![route, deadline + 1000],
                    |r| r.get::<_, u64>(0),
                )?,
                2
            );
            Ok(())
        })
    }

    fn wait_until(&self, offset: u64) -> Result<u64> {
        let elapsed = u64::try_from(self.clock.elapsed().as_millis())?;
        std::thread::sleep(std::time::Duration::from_millis(
            offset.saturating_sub(elapsed),
        ));
        Ok(NOW + u64::try_from(self.clock.elapsed().as_millis())?)
    }
}

#[test]
fn one_second_observations_continue_original_node_bounded_grants_across_refresh_and_restart()
-> Result {
    let mut f = ChainFixture::new([2, 2])?;
    for index in 0..2 {
        f.refresh(index, 2, NOW + 100, 1000, true)?;
    }
    let mut request = f.request()?;
    // Current node control leases are 10 seconds, so an eight-second grant
    // demonstrates independence from the one-second observation without
    // inventing authority beyond either existing node or business deadline.
    request.path.expires_at_unix_ms = NOW + 8000;
    f.sign(&mut request)?;
    let route = request.route_id.clone();
    let issued = f.issue_at(request, NOW + 100)?;
    let original_digests = issued.topology_digests;
    for index in 0..2 {
        f.refresh(index, 3, NOW + 700, 1000, true)?;
    }
    let now = f.wait_until(1200)?;
    for index in 0..2 {
        f.refresh(index, 4, now, 1000, true)?;
    }
    assert!(now > NOW + 1100);
    assert_ne!(f.digests, original_digests);
    let deployment = f.base.store.deployment_id()?;
    f.base.store = Store::from_snapshot(&f.base.store.snapshot()?, &deployment)?;
    let current = f.read_at(&route, now)?;
    assert_eq!(current.topology_digests, original_digests);
    assert_eq!(current.path.path.claims, issued.path.path.claims);
    assert_eq!(current.path.path.signature, issued.path.path.signature);
    for (original, current) in issued.transits.iter().zip(&current.transits) {
        assert_eq!(current.claims, original.claims);
        assert_eq!(current.signature, original.signature);
        assert_eq!(
            GrantClaims::decode_canonical(&current.claims)?
                .scope()
                .expires_at_ms,
            NOW + 8000
        );
    }
    Ok(())
}

#[test]
fn stale_initial_digest_is_rejected_even_when_a_new_head_continues_the_same_edge() -> Result {
    let mut f = ChainFixture::new([2, 2])?;
    let request = f.request()?;
    f.refresh(0, 2, NOW + 100, 1000, true)?;
    assert!(matches!(
        f.issue_at(request, NOW + 100),
        Err(StorageError::Conflict)
    ));
    let request = f.request()?;
    assert!(f.issue_at(request, NOW + 100).is_ok());
    Ok(())
}

#[test]
fn down_then_up_without_an_intermediate_poll_permanently_retires_both_original_hops() -> Result {
    let mut f = ChainFixture::new([2, 2])?;
    let request = f.request()?;
    let route = request.route_id.clone();
    let deadline = request.path.expires_at_unix_ms;
    f.issue(request)?;
    f.refresh(0, 2, NOW + 100, 1000, false)?;
    f.refresh(0, 3, NOW + 200, 1000, true)?;
    let deployment = f.base.store.deployment_id()?;
    f.base.store = Store::from_snapshot(&f.base.store.snapshot()?, &deployment)?;
    assert!(f.read_at(&route, NOW + 200).is_err());
    f.assert_retired_with_original_holds(&route, deadline)
}

#[test]
fn failed_report_journal_rolls_back_the_new_head_and_both_hop_retirements() -> Result {
    let mut f = ChainFixture::new([2, 2])?;
    let request = f.request()?;
    let route = request.route_id.clone();
    let issued = f.issue(request)?;
    edit_snapshot(&mut f.base, |db| {
        db.execute_batch("CREATE TRIGGER reject_topology_journal BEFORE INSERT ON network_topology_changes BEGIN SELECT RAISE(ABORT,'journal unavailable'); END;")
    })?;
    assert!(f.refresh(0, 2, NOW + 100, 1000, false).is_err());
    let current = f.read_at(&route, NOW + 100)?;
    assert_eq!(current.topology_digests, issued.topology_digests);
    for (current, original) in current.transits.iter().zip(&issued.transits) {
        assert_eq!(current.claims, original.claims);
        assert_eq!(current.signature, original.signature);
    }
    let space = f.base.space.clone();
    let node = f.nodes[0].0.clone();
    edit_snapshot(&mut f.base, |db| {
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM network_remote_chain_hops WHERE route_id=?1 AND closed=0",
                [&route],
                |r| r.get::<_, u64>(0),
            )?,
            2
        );
        assert_eq!(
            db.query_row(
                "SELECT sequence FROM network_topology_heads WHERE space_id=?1 AND node_id=?2",
                rusqlite::params![space, node],
                |r| r.get::<_, u64>(0),
            )?,
            1
        );
        Ok(())
    })
}

#[test]
fn expired_observation_cannot_be_repaired_into_the_original_chain_with_or_without_readback()
-> Result {
    for read_expired in [false, true] {
        let mut f = ChainFixture::new([2, 2])?;
        f.refresh(0, 2, NOW + 100, 200, true)?;
        let request = f.request()?;
        let route = request.route_id.clone();
        let deadline = request.path.expires_at_unix_ms;
        f.issue_at(request, NOW + 100)?;
        if read_expired {
            assert!(matches!(
                f.read_at(&route, NOW + 300),
                Err(StorageError::Forbidden)
            ));
            // This snapshot checks the HTTP read's error path actually committed
            // the retirement, before any new report could do it on our behalf.
            f.assert_retired_with_original_holds(&route, deadline)?;
        }
        f.refresh(0, 3, NOW + 300, 1000, true)?;
        assert!(f.read_at(&route, NOW + 300).is_err());
        f.assert_retired_with_original_holds(&route, deadline)?;
    }
    Ok(())
}

#[test]
fn replacement_publisher_with_identical_neighbors_never_inherits_an_old_chain() -> Result {
    let mut f = ChainFixture::new([2, 2])?;
    let request = f.request()?;
    let route = request.route_id.clone();
    let deadline = request.path.expires_at_unix_ms;
    f.issue(request)?;
    f.base.store.issue_topology_publisher(
        &f.base.controller,
        &f.base.signer,
        &f.base.space,
        &f.nodes[0].0,
        TopologyPublisherRequest {
            publisher_id: random_id(),
            expected_policy_epoch: 3,
            allowed_node_ids: vec![f.nodes[1].0.clone()],
            route_export_grant_ids: Vec::new(),
            expires_at_ms: NOW + 60_000,
        },
        NOW + 100,
    )?;
    f.refresh(0, 2, NOW + 100, 1000, true)?;
    assert!(f.read_at(&route, NOW + 100).is_err());
    f.assert_retired_with_original_holds(&route, deadline)
}

#[test]
fn schema_36_retires_unprovable_old_chains_without_refunding_or_resigning_them() -> Result {
    let mut f = ChainFixture::new([2, 2])?;
    let request = f.request()?;
    let route = request.route_id.clone();
    let deadline = request.path.expires_at_unix_ms;
    let issued = f.issue(request)?;
    edit_snapshot(&mut f.base, |db| {
        db.execute_batch(
            "DROP TABLE network_subnet_packet_bindings; DROP TABLE network_subnet_installations; ALTER TABLE network_packet_access DROP COLUMN subnet_binding_count; DROP TABLE network_subnet_mappings; DROP TABLE service_edge_group_ingress; DROP TABLE service_edge_groups; DROP INDEX service_definition_member_owner; DROP INDEX service_definition_owner; ALTER TABLE service_publications DROP COLUMN edge_group_id; ALTER TABLE service_publications DROP COLUMN edge_group_revision; CREATE UNIQUE INDEX service_definition_owner ON service_publications(service_id) WHERE state IN(0,1); DROP TABLE network_packet_access; DROP VIEW all_relay_capacity; DROP TABLE private_service_relay_hops; DROP TABLE private_service_usage_reports; DROP TABLE private_service_leases; DROP TABLE private_service_hosts; DROP TABLE private_service_acl; DROP TABLE service_exposures; DROP TABLE network_space_addresses; DROP TABLE network_space_address_directories; DROP TABLE network_remote_chain_topology_bindings; DROP TABLE network_remote_route_set_members; DROP TABLE network_remote_route_sets;
             CREATE VIEW all_relay_capacity AS SELECT id,kind,controller_account_id,host_account_id,node_id,promised_until FROM relay_reservations UNION ALL SELECT allocation_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_relays UNION ALL SELECT route_id,'node',controller_account_id,host_account_id,node_id,promised_until FROM network_remote_chain_hops;
             PRAGMA user_version=35;",
        )?;
        Ok(())
    })?;
    assert!(f.read(&route).is_err());
    f.assert_retired_with_original_holds(&route, deadline)?;
    edit_snapshot(&mut f.base, |db| {
        for (position, signed) in issued.transits.iter().enumerate() {
            let stored: (Vec<u8>, Vec<u8>) = db.query_row(
                "SELECT transit_claims,transit_signature FROM network_remote_chain_hops WHERE route_id=?1 AND position=?2",
                rusqlite::params![route,position as u8], |r|Ok((r.get(0)?,r.get(1)?)),
            )?;
            assert_eq!(stored.0, signed.claims);
            assert_eq!(stored.1, signed.signature);
        }
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM network_remote_chain_topology_bindings",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            0
        );
        Ok(())
    })
}
