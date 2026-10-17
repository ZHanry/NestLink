use super::*;
use nestlink_identity::node_discovery::discovery_transcript;
use nestlink_protocol::api::{NodeDiscoveryRequest, NodeEndpoints, NodeEndpointsUpdate};
use prost::Message;
impl Fixture {
    fn discovery(&self, host: bool) -> Result<NodeDiscoveryRequest> {
        let (actor, key, device) = if host {
            (&self.host, &self.h, &self.permit.host_device_id)
        } else {
            (&self.admin, &self.c, &self.permit.controller_device_id)
        };
        let nonce = [17; 32];
        let t = discovery_transcript(&self.permit, &actor.account_id, device, &nonce)?;
        Ok(NodeDiscoveryRequest {
            device_id: device.clone(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            permit_sha256: URL_SAFE_NO_PAD.encode(digest(&self.permit.encode_to_vec())),
            signature: URL_SAFE_NO_PAD.encode(key.sign_action(&t)?),
        })
    }
    fn approve_endpoints(&mut self, revision: u64, endpoints: NodeEndpoints) -> Result {
        self.s.set_node_endpoints(
            &self.admin,
            &self.node_id,
            NodeEndpointsUpdate {
                expected_revision: revision,
                endpoints,
            },
            NOW,
        )?;
        Ok(())
    }
    fn discover(&self, host: bool) -> Result<nestlink_protocol::NodeDiscoveryClaims> {
        Ok(self.s.discover_relay_nodes(
            &self.lifecycle,
            if host { &self.host } else { &self.admin },
            &self.permit.session_id,
            self.discovery(host)?,
            NOW,
        )?)
    }
}
fn locations() -> NodeEndpoints {
    NodeEndpoints {
        quic_uri: Some("quic://relay.example:28743".into()),
        wss_origin: Some("https://relay.example".into()),
        allow_loopback: false,
    }
}
#[test]
fn node_discovery_defaults_empty_and_reads_current_permit_without_reservation_or_lease_extension()
-> Result {
    let mut f = Fixture::new(false, 8)?;
    assert!(f.discover(false)?.nodes.is_empty());
    let before: (u64, u64) = f.s.connection.query_row(
        "SELECT lease_sequence,last_issued_at FROM data_nodes",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    f.approve_endpoints(0, locations())?;
    for host in [false, true] {
        let c = f.discover(host)?;
        assert_eq!(c.nodes.len(), 1);
        assert_eq!(c.nodes[0].endpoint_revision, 1);
        assert_eq!(c.nodes[0].node_key_sha256, digest(&f.node.public_key()));
        assert_eq!(
            c.expires_at_unix_ms,
            NOW + nestlink_protocol::NODE_DISCOVERY_MS
        );
    }
    assert_eq!(
        f.s.connection
            .query_row("SELECT count(*) FROM relay_reservations", [], |r| r
                .get::<_, u64>(0))?,
        0
    );
    assert_eq!(
        f.s.connection.query_row(
            "SELECT lease_sequence,last_issued_at FROM data_nodes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?))
        )?,
        before
    );
    assert_eq!(
        f.s.current_permit(&f.admin, &f.permit.session_id, NOW / 1000)?,
        f.permit
    );
    Ok(())
}
#[test]
fn node_endpoint_updates_require_current_admin_revision_and_audit_atomicity_and_survive_snapshot()
-> Result {
    let mut f = Fixture::new(false, 8)?;
    let update = || NodeEndpointsUpdate {
        expected_revision: 0,
        endpoints: locations(),
    };
    assert!(
        f.s.set_node_endpoints(&f.host, &f.node_id, update(), NOW)
            .is_err()
    );
    f.s.connection.execute(
        "UPDATE audit_settings SET high_watermark=9223372036854775807",
        [],
    )?;
    assert!(
        f.s.set_node_endpoints(&f.admin, &f.node_id, update(), NOW)
            .is_err()
    );
    assert_eq!(f.s.node_endpoints(&f.admin, &f.node_id, NOW)?.revision, 0);
    f.s.connection.execute(
        "UPDATE audit_settings SET high_watermark=(SELECT MAX(sequence) FROM audit)",
        [],
    )?;
    f.approve_endpoints(0, locations())?;
    assert!(
        f.s.set_node_endpoints(&f.admin, &f.node_id, update(), NOW)
            .is_err()
    );
    let restored = Store::from_snapshot(&f.s.snapshot()?, &f.s.deployment_id()?)?;
    assert_eq!(
        restored
            .node_endpoints(&f.admin, &f.node_id, NOW)?
            .endpoints,
        locations()
    );
    let audit: String = f.s.connection.query_row(
        "SELECT actor_json FROM audit WHERE event='node_endpoints_updated'",
        [],
        |r| r.get(0),
    )?;
    let actor: nestlink_protocol::api::AuditActor = serde_json::from_str(&audit)?;
    assert_eq!(actor, auditing::management(&f.admin));
    f.s.connection
        .execute("UPDATE data_nodes SET roles_json='[2]'", [])?;
    assert!(f.approve_endpoints(1, locations()).is_err());
    Ok(())
}
#[test]
fn node_discovery_requires_endpoint_possession_exact_permit_and_original_controller_login() -> Result
{
    let mut f = Fixture::new(false, 8)?;
    f.approve_endpoints(0, locations())?;
    for change in 0..4 {
        let mut req = f.discovery(false)?;
        match change {
            0 => req.signature = URL_SAFE_NO_PAD.encode([1; 64]),
            1 => req.nonce = URL_SAFE_NO_PAD.encode([18; 32]),
            2 => req.permit_sha256 = URL_SAFE_NO_PAD.encode([0; 32]),
            _ => req.device_id = f.permit.host_device_id.clone(),
        }
        assert!(
            f.s.discover_relay_nodes(&f.lifecycle, &f.admin, &f.permit.session_id, req, NOW)
                .is_err()
        );
    }
    let mut wrong = f.admin.clone();
    wrong.session_id = f.host.session_id.clone();
    assert!(
        f.s.discover_relay_nodes(
            &f.lifecycle,
            &wrong,
            &f.permit.session_id,
            f.discovery(false)?,
            NOW
        )
        .is_err()
    );
    f.s.connection.execute(
        "UPDATE management_sessions SET revoked=1 WHERE id=?1",
        [&f.admin.session_id],
    )?;
    assert!(f.discover(true).is_err()); // The original controller login remains mandatory.
    Ok(())
}
#[test]
fn node_endpoint_revision_invalidates_existing_grants_and_withdrawal_does_not_refund_capacity()
-> Result {
    let mut f = Fixture::new(false, 8)?;
    f.approve_endpoints(0, locations())?;
    let old = f.allocation()?;
    assert_eq!(old.node_endpoint_revision, 1);
    assert_eq!(f.resource_snapshot(NOW)?.allocations, vec![old.clone()]);
    f.approve_endpoints(
        1,
        NodeEndpoints {
            wss_origin: Some("https://other.example".into()),
            ..NodeEndpoints::default()
        },
    )?;
    assert!(f.resource_snapshot(NOW)?.allocations.is_empty());
    let req = f.request(&old.allocation_id)?;
    assert!(
        f.s.reserve_node_relay(&f.lifecycle, &f.admin, &f.permit.session_id, req, NOW)
            .is_err()
    );
    let next = f.allocation()?;
    assert_eq!(next.node_endpoint_revision, 2);
    assert_eq!(next.transports, vec![RelayTransport::WssStream as i32]);
    f.approve_endpoints(2, NodeEndpoints::default())?;
    assert!(f.discover(false)?.nodes.is_empty());
    assert!(f.allocation().is_err());
    assert_eq!(
        f.s.relay_reservation_usage(&f.admin, NOW)?.held_allocations,
        2
    );
    Ok(())
}
#[test]
fn node_discovery_filters_roles_node_capacity_live_runtime_and_policy_and_rejects_restore() -> Result
{
    let mut f = Fixture::new(false, 2)?;
    f.approve_endpoints(0, locations())?;
    assert_eq!(f.discover(false)?.nodes.len(), 1);
    f.allocation()?;
    // The other endpoint can still discover its existing reservation when the
    // first used the last node slot. This must not permit another UUID.
    assert_eq!(f.discover(true)?.nodes.len(), 1);
    assert!(f.allocation().is_err());
    f.s.connection
        .execute("UPDATE relay_reservations SET closed=1", [])?;
    assert!(f.discover(false)?.nodes.is_empty());
    f.s.connection.execute(
        "UPDATE relay_reservations SET closed=0,connection_generation=connection_generation+1",
        [],
    )?;
    assert!(f.discover(false)?.nodes.is_empty());
    f.s.connection.execute(
        "UPDATE relay_reservations SET connection_generation=connection_generation-1",
        [],
    )?;
    f.s.connection
        .execute("UPDATE relay_reservations SET promised_until=?1", [NOW])?;
    assert_eq!(f.discover(false)?.nodes.len(), 1);
    f.s.connection.execute(
        "UPDATE data_nodes SET lease_policy_revision=lease_policy_revision+1",
        [],
    )?;
    assert!(f.discover(false)?.nodes.is_empty());
    f.s.connection.execute(
        "UPDATE data_nodes SET lease_policy_revision=lease_policy_revision-1,last_issued_at=?1",
        [NOW - NODE_LEASE_MS],
    )?;
    assert!(f.discover(false)?.nodes.is_empty());
    f.s.connection.execute(
        "UPDATE data_nodes SET last_issued_at=?1,roles_json='[2]'",
        [NOW],
    )?;
    assert!(f.discover(false)?.nodes.is_empty());
    f.s.invalidate_after_restore()?;
    assert!(f.discover(false).is_err());
    Ok(())
}

#[test]
fn both_endpoints_discover_an_existing_allocation_at_global_account_and_node_capacity_without_new_quota()
-> Result {
    let mut f = Fixture::new(false, 2)?;
    f.approve_endpoints(0, locations())?;
    let mut quota = f.s.relay_quota_current()?;
    quota.limits.max_allocations = 1;
    quota.limits.max_account_endpoints = 1;
    f.s.set_relay_quota(
        &f.admin,
        RelayQuotaUpdate {
            expected_revision: quota.revision,
            limits: quota.limits,
        },
        NOW / 1000,
    )?;
    let allocation = f.allocation()?;
    let before = serde_json::to_value(f.s.relay_reservation_usage(&f.admin, NOW)?)?;
    for host in [false, true] {
        let discovered = f.discover(host)?;
        assert_eq!(discovered.nodes.len(), 1);
        assert!(discovered.nodes[0].expires_at_unix_ms <= allocation.expires_at_unix_ms);
    }
    let request = RelayAllocationRequest {
        allocation_id: allocation.allocation_id.clone(),
        node_id: f.node_id.clone(),
        device_id: f.permit.host_device_id.clone(),
        signature: URL_SAFE_NO_PAD.encode(f.h.sign_action(&allocation_transcript(
            &f.permit,
            &f.host.account_id,
            &f.permit.host_device_id,
            &allocation.allocation_id,
            &f.node_id,
        )?)?),
    };
    assert_eq!(
        f.s.reserve_node_relay(&f.lifecycle, &f.host, &f.permit.session_id, request, NOW)?,
        allocation
    );
    assert!(f.allocation().is_err());
    assert_eq!(
        serde_json::to_value(f.s.relay_reservation_usage(&f.admin, NOW)?)?,
        before
    );
    f.approve_endpoints(1, locations())?;
    assert!(f.discover(true)?.nodes.is_empty());
    assert_eq!(
        serde_json::to_value(f.s.relay_reservation_usage(&f.admin, NOW)?)?,
        before
    );
    Ok(())
}
