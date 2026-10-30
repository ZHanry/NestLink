use nestlink_protocol::{
    network::{IpPrefix, PeerId},
    network_topology::*,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const DEPLOYMENT: &str = "51fdac9e-235d-4688-8783-239f97457606";
const SPACE: &str = "f0c1429b-167b-4f87-897e-606f934e42ca";
const NODE: &str = "354ee49b-1873-4ca8-b978-afaf03f9d964";

fn report() -> TopologyReport {
    TopologyReport {
        schema_version: SCHEMA_VERSION,
        deployment_id: DEPLOYMENT.into(),
        space_id: SPACE.into(),
        policy_epoch: 1,
        node_id: NODE.into(),
        peer: PeerId([222; 32]),
        publisher_digest: [3; 32],
        incarnation: BootIncarnation {
            runtime_generation: 1,
            runtime_id: "1e1b93be-4dc0-46f7-9091-65ac7f0f6f69".into(),
        },
        sequence: 1,
        not_before_ms: 1000,
        expires_at_ms: 9000,
        neighbors: vec![],
        prefixes: vec![],
    }
}
fn withdrawal() -> TopologyWithdrawal {
    let report = report();
    TopologyWithdrawal {
        node_id: report.node_id,
        peer: report.peer,
        publisher_digest: report.publisher_digest,
        incarnation: report.incarnation,
        sequence: report.sequence,
    }
}
fn update(sync: TopologySync) -> TopologyUpdate {
    TopologyUpdate {
        schema_version: SCHEMA_VERSION,
        deployment_id: DEPLOYMENT.into(),
        space_id: SPACE.into(),
        policy_epoch: 1,
        query_nonce: [9; 32],
        issued_at_ms: 1000,
        expires_at_ms: 2000,
        sync,
    }
}

#[test]
fn canonical_reports_and_envelopes_reject_unknown_duplicate_and_noncanonical_json() -> Result {
    let bytes = report().canonical_bytes()?;
    assert_eq!(TopologyReport::decode_canonical(&bytes)?, report());
    let text = String::from_utf8(bytes.clone())?;
    let duplicate = text.replacen('{', "{\"schema_version\":1,", 1);
    assert!(TopologyReport::decode_canonical(duplicate.as_bytes()).is_err());
    let unknown = format!("{},\"extra\":true}}", &text[..text.len() - 1]);
    assert!(TopologyReport::decode_canonical(unknown.as_bytes()).is_err());
    let mut whitespace = vec![b' '];
    whitespace.extend_from_slice(&bytes);
    assert!(TopologyReport::decode_canonical(&whitespace).is_err());
    let signed = SignedTopologyReport {
        claims: bytes,
        signature: vec![7; 64],
    };
    assert_eq!(
        SignedTopologyReport::decode_canonical(&signed.canonical_bytes()?)?,
        signed
    );
    let mut malformed = signed;
    malformed.signature.push(0);
    assert!(malformed.validate().is_err());
    Ok(())
}

#[test]
fn reports_reject_default_routes_bad_incarnations_sequences_hops_and_size() -> Result {
    for (network, prefix_len) in [("0.0.0.0", 0), ("::", 0), ("127.0.0.0", 8)] {
        let mut invalid = report();
        invalid.prefixes = vec![IpPrefix {
            network: network.parse()?,
            prefix_len,
        }];
        assert!(invalid.canonical_bytes().is_err());
    }
    let mut invalid = report();
    invalid.incarnation.runtime_generation = 0;
    assert!(invalid.validate().is_err());
    invalid = report();
    invalid.sequence = 0;
    assert!(invalid.validate().is_err());
    invalid = report();
    invalid.expires_at_ms = invalid.not_before_ms + MAX_TTL_MS + 1;
    assert!(invalid.validate().is_err());
    invalid = report();
    invalid.neighbors = (0..=MAX_NEIGHBORS)
        .map(|index| TopologyNeighbor {
            local: invalid.peer,
            remote: PeerId([index as u8 + 1; 32]),
            local_endpoint_revision: 1,
            remote_endpoint_revision: 1,
            up: true,
        })
        .collect();
    assert!(invalid.validate().is_err());
    invalid.neighbors.truncate(1);
    invalid.neighbors[0].local = invalid.neighbors[0].remote;
    assert!(invalid.validate().is_err());
    assert!(TopologyReport::decode_canonical(&vec![b' '; MAX_REPORT_BYTES + 1]).is_err());
    Ok(())
}

#[test]
fn full_snapshot_and_delta_are_unambiguous_and_journal_cursors_are_bounded() -> Result {
    let full = update(TopologySync::Full {
        cursor: 0,
        advertisements: vec![],
    });
    assert_eq!(
        TopologyUpdate::decode_canonical(&full.canonical_bytes()?)?,
        full
    );
    let delta = update(TopologySync::Delta {
        after_cursor: 3,
        cursor: 4,
        has_more: false,
        changes: vec![TopologyDeltaEntry {
            cursor: 4,
            change: TopologyChange::Withdraw(withdrawal()),
        }],
    });
    assert_eq!(
        TopologyUpdate::decode_canonical(&delta.canonical_bytes()?)?,
        delta
    );
    let mut mixed = serde_json::to_value(&full)?;
    mixed["sync"]["changes"] = serde_json::json!([]);
    assert!(serde_json::from_value::<TopologyUpdate>(mixed).is_err());
    for (after_cursor, cursor, entries, has_more) in [
        (3, 5, vec![4], false),
        (3, 4, vec![3, 4], false),
        (3, 4, vec![4, 4], false),
        (3, 4, vec![], false),
        (3, 3, vec![], true),
    ] {
        assert!(
            update(TopologySync::Delta {
                after_cursor,
                cursor,
                has_more,
                changes: entries
                    .into_iter()
                    .map(|cursor| TopologyDeltaEntry {
                        cursor,
                        change: TopologyChange::Withdraw(withdrawal()),
                    })
                    .collect(),
            })
            .validate()
            .is_err()
        );
    }
    assert!(
        update(TopologySync::Delta {
            after_cursor: 0,
            cursor: MAX_DELTA as u64 + 1,
            has_more: false,
            changes: (1..=MAX_DELTA as u64 + 1)
                .map(|cursor| TopologyDeltaEntry {
                    cursor,
                    change: TopologyChange::Withdraw(withdrawal()),
                })
                .collect(),
        })
        .validate()
        .is_err()
    );
    Ok(())
}
