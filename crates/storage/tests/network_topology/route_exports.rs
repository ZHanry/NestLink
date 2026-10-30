use super::*;
use nestlink_identity::network::{SignedNetworkGrant, verify_network_grant};
use nestlink_protocol::network::{GrantClaims, IpPrefix, RouteExportClaims};
use nestlink_storage::network_policy::route_exports::{
    MAX_CURRENT_ROUTE_EXPORTS, MAX_ROUTE_EXPORT_HISTORY, MAX_ROUTE_EXPORT_MS, RouteExportRequest,
};
use rusqlite::{Connection, params};

fn prefix() -> Result<IpPrefix> {
    Ok(IpPrefix {
        network: "10.40.0.0".parse()?,
        prefix_len: 24,
    })
}
fn request(f: &mut Fixture, id: String, now: u64, expires: u64) -> Result<RouteExportRequest> {
    let snapshot = f.store.network_policy_snapshot(&f.space, now)?;
    Ok(RouteExportRequest {
        grant_id: id,
        expected_revision: snapshot.revision(),
        expected_policy_epoch: snapshot.policy_epoch(),
        prefixes: vec![prefix()?],
        expires_at_ms: expires,
    })
}
fn issue(
    f: &mut Fixture,
    node: usize,
    id: String,
    now: u64,
    expires: u64,
) -> Result<SignedNetworkGrant> {
    let request = request(f, id, now, expires)?;
    Ok(f.store.issue_network_route_export(
        &f.actor,
        &f.signer,
        &f.space,
        &f.nodes[node].0,
        request,
        now,
    )?)
}
fn publisher(f: &mut Fixture, node: usize, ids: Vec<String>, now: u64, expires: u64) -> Result {
    f.publishers[node] = f.store.issue_topology_publisher(
        &f.actor,
        &f.signer,
        &f.space,
        &f.nodes[node].0,
        TopologyPublisherRequest {
            publisher_id: random_id(),
            expected_policy_epoch: 1,
            allowed_node_ids: vec![f.nodes[1 - node].0.clone()],
            route_export_grant_ids: ids,
            expires_at_ms: expires,
        },
        now,
    )?;
    Ok(())
}
fn report(
    f: &mut Fixture,
    node: usize,
    sequence: u64,
    exports: &[SignedNetworkGrant],
    prefixes: Vec<IpPrefix>,
    now: u64,
    expires: u64,
) -> Result<SignedTopologyReport> {
    let snapshot = f.store.network_policy_snapshot(&f.space, now)?;
    let exports = exports
        .iter()
        .map(|grant| verify_network_grant(grant, &snapshot.verification()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (id, key, incarnation) = &f.nodes[node];
    let publisher = verify_topology_publisher(
        &f.publishers[node],
        &snapshot.verification(),
        id,
        &key.public_key(),
        incarnation,
        &exports,
    )?;
    Ok(key.sign_topology_report(&TopologyReport {
        schema_version: 1,
        deployment_id: f.deployment.clone(),
        space_id: f.space.clone(),
        policy_epoch: 1,
        node_id: id.clone(),
        peer: PeerId::from_public_key(&key.public_key()),
        publisher_digest: publisher.digest(),
        incarnation: incarnation.clone(),
        sequence,
        not_before_ms: now,
        expires_at_ms: expires,
        neighbors: vec![TopologyNeighbor {
            local: PeerId::from_public_key(&key.public_key()),
            remote: PeerId::from_public_key(&f.nodes[1 - node].1.public_key()),
            local_endpoint_revision: 1,
            remote_endpoint_revision: 1,
            up: true,
        }],
        prefixes,
    })?)
}

#[test]
fn stored_exports_bind_node_space_and_exact_committed_bytes_across_restart() -> Result {
    let mut f = Fixture::new()?;
    let id = random_id();
    let signed = issue(&mut f, 0, id.clone(), NOW + 10, NOW + 60_000)?;
    let snapshot = f.store.network_policy_snapshot(&f.space, NOW + 10)?;
    let verified = verify_network_grant(&signed, &snapshot.verification())?;
    let GrantClaims::RouteExport(export) = verified.claims() else {
        return Err("wrong grant kind".into());
    };
    assert_eq!(
        export.gateway,
        PeerId::from_public_key(&f.nodes[0].1.public_key())
    );
    assert_eq!(export.prefixes, vec![prefix()?]);
    f.restart()?;
    let read = f
        .store
        .network_route_export(&f.actor, &f.space, &id, NOW + 20)?;
    assert_eq!(read.claims, signed.claims);
    assert_eq!(read.signature, signed.signature);
    assert!(
        f.store
            .network_route_export(&f.stranger, &f.space, &id, NOW + 20)
            .is_err()
    );
    let mut retry = request(&mut f, id.clone(), NOW + 20, NOW + 90_000)?;
    assert!(matches!(
        f.store.issue_network_route_export(
            &f.actor,
            &f.signer,
            &f.space,
            &f.nodes[0].0,
            retry.clone(),
            NOW + 20
        ),
        Err(StorageError::Conflict)
    ));
    retry.grant_id = random_id();
    assert!(
        f.store
            .issue_network_route_export(
                &f.stranger,
                &f.signer,
                &f.space,
                &f.nodes[0].0,
                retry,
                NOW + 20
            )
            .is_err()
    );
    assert!(publisher(&mut f, 1, vec![id], NOW + 20, NOW + 50_000).is_err());
    Ok(())
}

#[test]
fn exact_prefix_chain_enters_real_journal_and_export_revocation_withdraws_atomically() -> Result {
    let mut f = Fixture::new()?;
    let id = random_id();
    let export = issue(&mut f, 0, id.clone(), NOW + 10, NOW + 60_000)?;
    publisher(&mut f, 0, vec![id.clone()], NOW + 20, NOW + 50_000)?;
    let signed = report(
        &mut f,
        0,
        7,
        std::slice::from_ref(&export),
        vec![prefix()?],
        NOW + 30,
        NOW + 1030,
    )?;
    let ad = f.accept(0, &signed, NOW + 30)?;
    assert_eq!(
        TopologyAdvertisement::decode_canonical(&ad.claims)?
            .report
            .prefixes,
        vec![prefix()?]
    );
    let peer_report = f.report(1, 1, NOW + 40)?;
    f.accept(1, &peer_report, NOW + 40)?; // Revalidates the other node's export-bearing publisher.
    assert!(
        matches!(f.sync(None,NOW+50)?,TopologySync::Full {cursor:2,advertisements} if advertisements.len()==2)
    );
    let snapshot = f.store.network_policy_snapshot(&f.space, NOW + 60)?;
    assert!(matches!(
        f.store.revoke_network_route_export(
            &f.actor,
            &f.space,
            &id,
            snapshot.revision() + 1,
            NOW + 60
        ),
        Err(StorageError::Conflict)
    ));
    let revoked = f.store.revoke_network_route_export(
        &f.actor,
        &f.space,
        &id,
        snapshot.revision(),
        NOW + 60,
    )?;
    assert!(revoked.verification().revoked_grant_ids.contains(&id));
    assert_eq!(revoked.policy_epoch(), 1);
    assert!(verify_network_grant(&export, &revoked.verification()).is_err());
    assert!(
        f.store
            .topology_publisher(&f.actor, &f.space, &f.nodes[0].0, NOW + 60)
            .is_err()
    );
    assert!(f.accept(0, &signed, NOW + 160).is_err());
    assert!(
        matches!(f.sync(Some(2),NOW+160)?,TopologySync::Delta {changes,..} if changes.iter().any(|entry|matches!(&entry.change,TopologyChange::Withdraw(w) if w.node_id==f.nodes[0].0 && w.sequence==7)))
    );
    f.restart()?;
    assert!(
        f.store
            .network_route_export(&f.actor, &f.space, &id, NOW + 170)
            .is_err()
    );
    let second_id = random_id();
    let second = issue(&mut f, 0, second_id.clone(), NOW + 180, NOW + 60_000)?;
    publisher(&mut f, 0, vec![second_id], NOW + 190, NOW + 50_000)?;
    let old_sequence = report(
        &mut f,
        0,
        7,
        std::slice::from_ref(&second),
        vec![prefix()?],
        NOW + 200,
        NOW + 1200,
    )?;
    assert!(f.accept(0, &old_sequence, NOW + 200).is_err());
    let next = report(
        &mut f,
        0,
        8,
        std::slice::from_ref(&second),
        vec![prefix()?],
        NOW + 210,
        NOW + 1210,
    )?;
    f.accept(0, &next, NOW + 210)?;
    Ok(())
}

#[test]
fn prefixes_still_need_exact_stored_authority_and_cannot_expand_their_permission() -> Result {
    let mut f = Fixture::new()?;
    let snapshot = f.store.network_policy_snapshot(&f.space, NOW + 10)?;
    let id = random_id();
    let external = f.signer.sign(&GrantClaims::RouteExport(RouteExportClaims {
        scope: nestlink_protocol::network::GrantScope {
            schema_version: 1,
            deployment_id: f.deployment.clone(),
            space_id: f.space.clone(),
            grant_id: id.clone(),
            policy_epoch: 1,
            not_before_ms: NOW + 10,
            expires_at_ms: NOW + 60_000,
        },
        gateway: PeerId::from_public_key(&f.nodes[0].1.public_key()),
        prefixes: vec![prefix()?],
    }))?;
    verify_network_grant(&external, &snapshot.verification())?;
    assert!(publisher(&mut f, 0, vec![id], NOW + 20, NOW + 50_000).is_err());
    let id = random_id();
    let export = issue(&mut f, 0, id.clone(), NOW + 20, NOW + 60_000)?;
    publisher(&mut f, 0, vec![id], NOW + 30, NOW + 50_000)?;
    let forged = report(
        &mut f,
        0,
        1,
        std::slice::from_ref(&export),
        vec![IpPrefix {
            network: "10.41.0.0".parse()?,
            prefix_len: 24,
        }],
        NOW + 40,
        NOW + 1040,
    )?;
    assert!(f.accept(0, &forged, NOW + 40).is_err());
    let valid = report(
        &mut f,
        0,
        1,
        std::slice::from_ref(&export),
        vec![prefix()?],
        NOW + 50,
        NOW + 1050,
    )?;
    f.accept(0, &valid, NOW + 50)?;
    Ok(())
}

#[test]
fn export_issuance_rejects_wrong_revision_epoch_authority_prefix_and_lifetime() -> Result {
    let mut f = Fixture::new()?;
    let template = request(&mut f, random_id(), NOW + 10, NOW + 60_000)?;
    let mut cases = Vec::new();
    let mut wrong = template.clone();
    wrong.expected_revision += 1;
    cases.push(wrong);
    let mut wrong = template.clone();
    wrong.expected_policy_epoch += 1;
    cases.push(wrong);
    let mut wrong = template.clone();
    wrong.expires_at_ms = NOW + 10;
    cases.push(wrong);
    let mut wrong = template.clone();
    wrong.expires_at_ms = NOW + 11 + MAX_ROUTE_EXPORT_MS;
    cases.push(wrong);
    let mut wrong = template.clone();
    wrong.prefixes.clear();
    cases.push(wrong);
    let mut wrong = template.clone();
    wrong.prefixes.push(prefix()?);
    cases.push(wrong);
    let mut wrong = template.clone();
    wrong.prefixes = vec![IpPrefix {
        network: "0.0.0.0".parse()?,
        prefix_len: 0,
    }];
    cases.push(wrong);
    let mut wrong = template.clone();
    wrong.prefixes = vec![IpPrefix {
        network: "10.40.0.1".parse()?,
        prefix_len: 24,
    }];
    cases.push(wrong);
    let mut wrong = template.clone();
    wrong.prefixes = (0..33)
        .map(|last| {
            Ok(IpPrefix {
                network: format!("10.40.{last}.0").parse()?,
                prefix_len: 24,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    cases.push(wrong);
    for request in cases {
        assert!(
            f.store
                .issue_network_route_export(
                    &f.actor,
                    &f.signer,
                    &f.space,
                    &f.nodes[0].0,
                    request,
                    NOW + 10
                )
                .is_err()
        );
    }
    let other = NetworkAuthoritySigner::from_master_seed(&[88; 32])?;
    assert!(
        f.store
            .issue_network_route_export(
                &f.actor,
                &other,
                &f.space,
                &f.nodes[0].0,
                template,
                NOW + 10
            )
            .is_err()
    );
    assert_eq!(
        f.store
            .network_policy_snapshot(&f.space, NOW + 10)?
            .revision(),
        1
    );
    Ok(())
}

#[test]
fn publisher_deadlines_duplicates_and_cross_kind_ids_do_not_bypass_stored_exports() -> Result {
    let mut f = Fixture::new()?;
    let id = random_id();
    issue(&mut f, 0, id.clone(), NOW + 10, NOW + 1000)?;
    assert!(publisher(&mut f, 0, vec![id.clone()], NOW + 20, NOW + 1001).is_err());
    assert!(publisher(&mut f, 0, vec![id.clone(), id.clone()], NOW + 20, NOW + 900).is_err());
    let publisher_id = TopologyPublisherClaims::decode_canonical(&f.publishers[0].claims)?
        .scope
        .grant_id;
    let cross = request(&mut f, publisher_id, NOW + 20, NOW + 900)?;
    assert!(matches!(
        f.store.issue_network_route_export(
            &f.actor,
            &f.signer,
            &f.space,
            &f.nodes[0].0,
            cross.clone(),
            NOW + 20
        ),
        Err(StorageError::Conflict)
    ));
    let original_pub = f.publishers[0].clone();
    let conflict = f.store.issue_topology_publisher(
        &f.actor,
        &f.signer,
        &f.space,
        &f.nodes[0].0,
        TopologyPublisherRequest {
            publisher_id: id.clone(),
            expected_policy_epoch: 1,
            allowed_node_ids: vec![],
            route_export_grant_ids: vec![],
            expires_at_ms: NOW + 900,
        },
        NOW + 20,
    );
    assert!(matches!(conflict, Err(StorageError::Conflict)));
    assert_eq!(
        f.store
            .topology_publisher(&f.actor, &f.space, &f.nodes[0].0, NOW + 20)?
            .claims,
        original_pub.claims
    );
    publisher(&mut f, 0, vec![id.clone()], NOW + 30, NOW + 900)?;
    assert!(
        f.store
            .network_route_export(&f.actor, &f.space, &id, NOW + 1000)
            .is_err()
    );
    assert!(
        f.store
            .topology_publisher(&f.actor, &f.space, &f.nodes[0].0, NOW + 1000)
            .is_err()
    );
    Ok(())
}

#[test]
fn node_revocation_and_clock_rollback_invalidate_publication_proofs() -> Result {
    let mut f = Fixture::new()?;
    let id = random_id();
    let export = issue(&mut f, 0, id.clone(), NOW + 10, NOW + 60_000)?;
    f.store
        .network_route_export(&f.actor, &f.space, &id, NOW + 20)?;
    assert!(matches!(
        f.store
            .network_route_export(&f.actor, &f.space, &id, NOW + 19),
        Err(StorageError::Conflict)
    ));
    f.store.revoke_node(&f.actor, &f.nodes[0].0)?;
    let snapshot = f.store.network_policy_snapshot(&f.space, NOW + 30)?;
    assert!(snapshot.verification().revoked_grant_ids.contains(&id));
    assert!(verify_network_grant(&export, &snapshot.verification()).is_err());
    assert!(
        f.store
            .network_route_export(&f.actor, &f.space, &id, NOW + 30)
            .is_err()
    );
    let snapshot = f.store.network_policy_snapshot(&f.space, NOW + 40)?;
    let revoked = f.store.revoke_network_route_export(
        &f.actor,
        &f.space,
        &id,
        snapshot.revision(),
        NOW + 40,
    )?;
    let again = f.store.revoke_network_route_export(
        &f.actor,
        &f.space,
        &id,
        revoked.revision(),
        NOW + 50,
    )?;
    assert_eq!(again.revision(), revoked.revision());
    assert!(issue(&mut f, 1, id, NOW + 60, NOW + 60_000).is_err());
    Ok(())
}

#[test]
fn expired_export_chain_withdraws_its_live_head_without_resetting_sequence() -> Result {
    let mut f = Fixture::new()?;
    let id = random_id();
    let export = issue(&mut f, 0, id.clone(), NOW + 10, NOW + 900)?;
    publisher(&mut f, 0, vec![id], NOW + 20, NOW + 900)?;
    let signed = report(
        &mut f,
        0,
        19,
        std::slice::from_ref(&export),
        vec![prefix()?],
        NOW + 30,
        NOW + 900,
    )?;
    f.accept(0, &signed, NOW + 30)?;
    assert!(
        matches!(f.sync(None,NOW+40)?,TopologySync::Full {cursor:1,advertisements} if advertisements.len()==1)
    );
    assert!(
        matches!(f.sync(Some(1),NOW+900)?,TopologySync::Delta {cursor:2,changes,..} if changes.len()==1 && matches!(&changes[0].change,TopologyChange::Withdraw(w) if w.sequence==19))
    );
    assert!(f.accept(0, &signed, NOW + 1000).is_err());
    Ok(())
}

#[test]
fn route_export_capacity_and_permanent_history_budgets_fail_closed() -> Result {
    let mut f = Fixture::new()?;
    let id = random_id();
    issue(&mut f, 0, id.clone(), NOW + 10, NOW + 60_000)?;
    let db = Connection::open(f.directory.path().join("control.sqlite3"))?;
    // Populate capacity metadata from one real signed record. These cloned
    // rows are deliberately never admitted as credentials: production readback
    // rejects their scope IDs. This tests the database resource fences without
    // manufacturing tens of thousands of unnecessary signing operations.
    db.execute("WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM ids WHERE n<?3) INSERT INTO network_route_exports(space_id,grant_id,node_id,public_key,policy_epoch,digest,claims,signature,issued_at_ms,expires_at_ms,revoked) SELECT e.space_id,printf('00000000-0000-4000-8000-%012x',ids.n),e.node_id,e.public_key,e.policy_epoch,randomblob(32),e.claims,e.signature,e.issued_at_ms,e.expires_at_ms,0 FROM network_route_exports e,ids WHERE e.space_id=?1 AND e.grant_id=?2",params![f.space,id,MAX_CURRENT_ROUTE_EXPORTS-1])?;
    let req = request(&mut f, random_id(), NOW + 20, NOW + 60_000)?;
    assert!(matches!(
        f.store.issue_network_route_export(
            &f.actor,
            &f.signer,
            &f.space,
            &f.nodes[0].0,
            req,
            NOW + 20
        ),
        Err(StorageError::RateLimited)
    ));
    db.execute(
        "UPDATE network_route_exports SET revoked=1 WHERE space_id=?1",
        [&f.space],
    )?;
    db.execute("WITH RECURSIVE ids(n) AS (SELECT ?3 UNION ALL SELECT n+1 FROM ids WHERE n<?4) INSERT INTO network_route_exports(space_id,grant_id,node_id,public_key,policy_epoch,digest,claims,signature,issued_at_ms,expires_at_ms,revoked) SELECT e.space_id,printf('00000000-0000-4000-8000-%012x',ids.n),e.node_id,e.public_key,e.policy_epoch,randomblob(32),e.claims,e.signature,e.issued_at_ms,e.expires_at_ms,1 FROM network_route_exports e,ids WHERE e.space_id=?1 AND e.grant_id=?2",params![f.space,id,MAX_CURRENT_ROUTE_EXPORTS,MAX_ROUTE_EXPORT_HISTORY-1])?;
    let req = request(&mut f, random_id(), NOW + 30, NOW + 60_000)?;
    assert!(matches!(
        f.store.issue_network_route_export(
            &f.actor,
            &f.signer,
            &f.space,
            &f.nodes[0].0,
            req,
            NOW + 30
        ),
        Err(StorageError::RateLimited)
    ));
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM network_route_exports WHERE space_id=?1",
            [&f.space],
            |r| r.get::<_, usize>(0)
        )?,
        MAX_ROUTE_EXPORT_HISTORY
    );
    Ok(())
}

#[test]
fn schema_35_upgrade_preserves_existing_signed_topology_and_original_sequence() -> Result {
    let mut f = Fixture::new()?;
    let signed = f.report(0, 11, NOW + 10)?;
    let original = f.accept(0, &signed, NOW + 10)?;
    let db = Connection::open(f.directory.path().join("control.sqlite3"))?;
    db.execute_batch("DROP TABLE network_topology_publisher_exports; DROP TABLE network_route_exports; PRAGMA user_version=34;")?;
    drop(db);
    f.restart()?;
    let retry = f.accept(0, &signed, NOW + 20)?;
    assert_eq!(retry.claims, original.claims);
    assert_eq!(retry.signature, original.signature);
    let id = random_id();
    issue(&mut f, 0, id, NOW + 30, NOW + 60_000)?;
    Ok(())
}
