use super::*;
use nestlink_identity::{digest, nodes::NodeIdentity, relay::allocation_transcript};
use nestlink_protocol::{
    DeviceAction, DeviceActionClaims, NodeRole,
    api::{NodeEndpoints, NodeEndpointsUpdate, NodeRegistration},
};
use prost::Message;

fn relay_body(f: &Fixture, remote: &RemoteSetup) -> Result<(Value, NodeIdentity, String)> {
    let mut store = Store::open_existing(&f.database, &f.deployment)?;
    let now_ms = current_ms()?;
    let actor = store.authenticate(&f.admin_token, now_ms / 1000)?;
    let business = store.current_permit(&actor, &remote.request, now_ms / 1000)?;
    let node = NodeIdentity::generate();
    let node_id = random_id();
    store.register_node(
        &actor,
        NodeRegistration {
            id: node_id.clone(),
            name: "network relay".into(),
            public_key: URL_SAFE_NO_PAD.encode(node.public_key()),
            roles: vec![NodeRole::NodeRelay as i32],
            max_connections: 10,
            bytes_per_second: 100_000,
        },
    )?;
    store.set_node_endpoints(
        &actor,
        &node_id,
        NodeEndpointsUpdate {
            expected_revision: 0,
            endpoints: NodeEndpoints {
                quic_uri: Some("quic://127.0.0.1:28744".into()),
                wss_origin: None,
                allow_loopback: true,
            },
        },
        now_ms,
    )?;
    let challenge = store.node_challenge(&node_id, now_ms)?;
    store.issue_node_lease(&node.prove(&challenge, &random_id())?, now_ms)?;
    let allocation = random_id();
    let transcript = if business.paths.contains(&(Path::Relay as i32)) {
        allocation_transcript(
            &business,
            &actor.account_id,
            &business.controller_device_id,
            &allocation,
            &node_id,
        )?
    } else {
        // An untrusted client can sign a well-formed allocation action even
        // though the consent-aware SDK constructor refuses a direct-only permit.
        // Send the exact device-action domain and canonical tuple to HTTP so
        // production admission, rather than fixture preflight, rejects it.
        assert_eq!(business.paths, vec![Path::Direct as i32]);
        DeviceActionClaims {
            schema_version: business.schema_version,
            action: DeviceAction::RelayAllocate as i32,
            deployment_id: business.deployment_id.clone(),
            security_epoch: business.security_epoch,
            account_id: actor.account_id.clone(),
            device_id: business.controller_device_id.clone(),
            resource_id: business.session_id.clone(),
            challenge: digest(&business.encode_to_vec()).to_vec(),
            payload_sha256: digest(format!("{allocation}\0{node_id}").as_bytes()).to_vec(),
            expires_at_unix_ms: business.expires_at_unix_ms,
        }
    };
    let signature = URL_SAFE_NO_PAD.encode(remote.controller_key.sign_action(&transcript)?);
    Ok((
        json!({
            "path":remote.body(), "transit_grant_id":random_id(),
            "allocation":{"allocation_id":allocation,"node_id":node_id,"device_id":business.controller_device_id,"signature":signature},
        }),
        node,
        node_id,
    ))
}

#[tokio::test]
async fn live_observation_and_exhausted_issuance_do_not_consume_revocation_capacity() -> Result {
    let f = Fixture::new(false).await?;
    let remote = setup_remote_with_path(&f, true, false)?;
    let (body, _, _) = relay_body(&f, &remote)?;
    let issue = format!("{}/remote/{}/relays", f.base(), remote.request);
    let allocation = body["allocation"]["allocation_id"]
        .as_str()
        .ok_or("allocation missing")?;
    let endpoint = format!("{}/relays/{allocation}", f.base());
    let (status, issued) = f
        .call("POST", &issue, body.clone(), Some(&f.admin_token))
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    // More than the issuance budget, using the actual authenticated readback
    // and complete signed route. Observation must not terminate a healthy path.
    for _ in 0..40 {
        let (status, observed) = f
            .call("GET", &endpoint, Value::Null, Some(&f.admin_token))
            .await?;
        assert_eq!(status, StatusCode::OK, "{observed}");
        assert_eq!(observed, issued);
    }
    // The original creation consumed one issuance slot. Replays are still
    // denied and still consume the same bounded issuance budget.
    for _ in 0..29 {
        assert_eq!(
            f.call("POST", &issue, body.clone(), Some(&f.admin_token))
                .await?
                .0,
            StatusCode::CONFLICT
        );
    }
    assert_eq!(
        f.call("POST", &issue, body, Some(&f.admin_token)).await?.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        f.call("DELETE", &endpoint, Value::Null, Some(&f.admin_token))
            .await?
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.call("GET", &endpoint, Value::Null, Some(&f.admin_token))
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test]
async fn relay_http_issues_exact_business_bound_transit_and_retains_capacity_after_revoke() -> Result
{
    let f = Fixture::new(false).await?;
    let remote = setup_remote_with_path(&f, true, false)?;
    let (body, node, _) = relay_body(&f, &remote)?;
    let issue = format!("{}/remote/{}/relays", f.base(), remote.request);
    let allocation = body["allocation"]["allocation_id"]
        .as_str()
        .ok_or("allocation missing")?;
    let endpoint = format!("{}/relays/{allocation}", f.base());
    assert_eq!(
        f.call("POST", &issue, body.clone(), None).await?.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, issued) = f
        .call("POST", &issue, body.clone(), Some(&f.admin_token))
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    assert_eq!(issued["allocation_id"], allocation);
    assert_eq!(issued["path"]["request_id"], remote.request);
    assert_eq!(issued["node"]["revision"], 1);
    assert_eq!(
        issued["node"]["endpoints"]["quic_uri"],
        "quic://127.0.0.1:28744"
    );
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: &f.issuer,
        deployment_id: &f.deployment,
        space_id: &f.space,
        policy_epoch: 3,
        now_ms: current_ms()?,
        revoked_grant_ids: &revoked,
    };
    let transit = verify_network_grant(&signed(&issued["transit"])?, &context)?;
    let GrantClaims::Transit(claims) = transit.claims() else {
        return Err("not transit".into());
    };
    assert_eq!(claims.route_id, allocation);
    assert_eq!(
        claims.relay,
        nestlink_protocol::network::PeerId::from_public_key(&node.public_key())
    );
    assert_eq!(claims.previous, claims.peers.first);
    assert_eq!(claims.next, claims.peers.second);
    assert_eq!(claims.remaining_hops, 1);
    let path = verify_network_grant(&signed(&issued["path"]["path"])?, &context)?;
    let GrantClaims::Path(path_claims) = path.claims() else {
        return Err("not path".into());
    };
    assert!(!path_claims.policy.allow_direct);
    assert_eq!(path_claims.policy.relays, vec![claims.relay]);
    assert_eq!(path_claims.policy.max_hops, 1);
    for token in [&f.admin_token, &f.member_token] {
        let (status, read) = f.call("GET", &endpoint, Value::Null, Some(token)).await?;
        assert_eq!(status, StatusCode::OK, "{read}");
        assert_eq!(read, issued);
    }
    assert_eq!(
        f.call("POST", &issue, body.clone(), Some(&f.admin_token))
            .await?
            .0,
        StatusCode::CONFLICT
    );
    let db = Connection::open(&f.database)?;
    let (persisted, promised): (Vec<u8>, u64) = db.query_row(
        "SELECT transit_claims,promised_until FROM network_remote_relays WHERE allocation_id=?1",
        [allocation],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    assert_eq!(persisted, signed(&issued["transit"])?.claims);
    assert_eq!(promised, claims.scope.expires_at_ms + 1000);
    for _ in 0..2 {
        assert_eq!(
            f.call("DELETE", &endpoint, Value::Null, Some(&f.member_token))
                .await?
                .0,
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        f.call("GET", &endpoint, Value::Null, Some(&f.admin_token))
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, usage) = f
        .call(
            "GET",
            "/api/v3/relay/reservations",
            Value::Null,
            Some(&f.admin_token),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(usage["held_allocations"], 1);
    assert_eq!(usage["held_endpoint_slots"], 2);
    assert_eq!(
        db.query_row(
            "SELECT promised_until FROM network_remote_relays WHERE allocation_id=?1",
            [allocation],
            |r| r.get::<_, u64>(0)
        )?,
        promised
    );
    Ok(())
}

#[tokio::test]
async fn relay_http_rejects_forged_proof_cookies_unknown_claims_and_changed_node_facts() -> Result {
    let f = Fixture::new(false).await?;
    let remote = setup_remote_with_path(&f, true, false)?;
    let (body, _, node_id) = relay_body(&f, &remote)?;
    let issue = format!("{}/remote/{}/relays", f.base(), remote.request);
    let mut forged = body.clone();
    forged["allocation"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0; 64]));
    assert_eq!(
        f.call("POST", &issue, forged, Some(&f.admin_token))
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    for (field, value) in [
        ("relays", json!([random_id()])),
        ("byte_limit", json!(u64::MAX)),
        ("claims", json!({})),
    ] {
        let mut unknown = body.clone();
        unknown[field] = value;
        assert_eq!(
            f.call("POST", &issue, unknown, Some(&f.admin_token))
                .await?
                .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    let cookie = format!("nl15_access={}", f.admin_token);
    assert_eq!(
        f.call_headers(
            "POST",
            &issue,
            body.clone(),
            None,
            &[("Cookie", &cookie), ("Origin", "https://attacker.invalid")]
        )
        .await?
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, issued) = f.call("POST", &issue, body, Some(&f.admin_token)).await?;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    let allocation = issued["allocation_id"]
        .as_str()
        .ok_or("allocation missing")?;
    let endpoint = format!("{}/relays/{allocation}", f.base());
    for method in ["GET", "DELETE"] {
        assert_eq!(
            f.call(method, &endpoint, Value::Null, None).await?.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        f.call(
            "GET",
            &format!("/api/v3/network/spaces/{}/relays/{allocation}", random_id()),
            Value::Null,
            Some(&f.admin_token)
        )
        .await?
        .0,
        StatusCode::FORBIDDEN
    );
    let db = Connection::open(&f.database)?;
    db.execute(
        "UPDATE node_endpoints SET revision=revision+1 WHERE node_id=?1",
        [&node_id],
    )?;
    assert_eq!(
        f.call("GET", &endpoint, Value::Null, Some(&f.member_token))
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    db.execute(
        "UPDATE node_endpoints SET revision=revision-1 WHERE node_id=?1",
        [&node_id],
    )?;
    db.execute(
        "UPDATE sessions SET connection_generation=connection_generation+1 WHERE id=?1",
        [&remote.request],
    )?;
    assert_eq!(
        f.call("GET", &endpoint, Value::Null, Some(&f.member_token))
            .await?
            .0,
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test]
async fn relay_http_cannot_widen_direct_only_business_consent() -> Result {
    let f = Fixture::new(false).await?;
    let remote = setup_remote(&f, true)?;
    let (body, _, _) = relay_body(&f, &remote)?;
    let issue = format!("{}/remote/{}/relays", f.base(), remote.request);
    assert_eq!(
        f.call("POST", &issue, body, Some(&f.admin_token)).await?.0,
        StatusCode::FORBIDDEN
    );
    let db = Connection::open(&f.database)?;
    assert_eq!(
        db.query_row("SELECT count(*) FROM network_remote_relays", [], |r| r
            .get::<_, u64>(0))?,
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM network_remote_paths", [], |r| r
            .get::<_, u64>(0))?,
        0
    );
    Ok(())
}
