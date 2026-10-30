use super::*;

#[tokio::test]
async fn authority_http_rotation_signs_current_credentials_and_permanent_revoke_is_admin_only()
-> Result {
    let f = Fixture::new(false).await?;
    f.setup_space().await?;
    let old_id = random_id();
    let old = f.issue(&old_id, 2, 1).await?;
    let authority = format!("{}/authority", f.base());
    let rotate = format!("{authority}/rotate");
    let advance = format!("{}/policy/advance", f.base());
    let change = json!({"expected_revision":2,"expected_policy_epoch":2});
    for (token, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(f.member_token.as_str()), StatusCode::FORBIDDEN),
    ] {
        let (status, _) = f.call("POST", &rotate, change.clone(), token).await?;
        assert_eq!(status, expected);
    }
    let (status, initial) = f
        .call("GET", &authority, Value::Null, Some(&f.admin_token))
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(initial["signing_generation"], 0);
    let (status, rotated) = f
        .call("POST", &rotate, change.clone(), Some(&f.admin_token))
        .await?;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    assert_eq!(rotated["signing_generation"], 1);
    assert_eq!(rotated["policy"]["revision"], 3);
    assert_eq!(rotated["policy"]["policy_epoch"], 3);
    assert_ne!(
        rotated["policy"]["authority_public_key"],
        initial["policy"]["authority_public_key"]
    );
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(
            rotated["policy"]["authority_public_key"]
                .as_str()
                .ok_or("new key missing")?,
        )?
        .as_slice()
        .try_into()?;
    let fresh = f.issue(&random_id(), 3, 1).await?;
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: &key,
        deployment_id: &f.deployment,
        space_id: &f.space,
        policy_epoch: 3,
        now_ms: current_ms()?,
        revoked_grant_ids: &revoked,
    };
    verify_network_grant(&signed(&fresh)?, &context)?;
    assert!(verify_network_grant(&signed(&old)?, &context).is_err());
    let (status, _) = f
        .call(
            "GET",
            &format!("{}/grants/{old_id}", f.base()),
            Value::Null,
            Some(&f.admin_token),
        )
        .await?;
    assert!(!status.is_success());
    let (status, _) = f
        .call("POST", &rotate, change, Some(&f.admin_token))
        .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = f
        .call(
            "PUT",
            &authority,
            json!({"expected_revision":3}),
            Some(&f.admin_token),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, advanced) = f
        .call(
            "POST",
            &advance,
            json!({"expected_revision":3,"expected_policy_epoch":3}),
            Some(&f.admin_token),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(advanced["policy_epoch"], 4);
    assert_eq!(
        advanced["authority_public_key"],
        rotated["policy"]["authority_public_key"]
    );
    let change = json!({"expected_revision":4,"expected_policy_epoch":4});
    let (status, _) = f
        .call("DELETE", &authority, change.clone(), Some(&f.member_token))
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = f
        .call("DELETE", &authority, change, Some(&f.admin_token))
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, terminal) = f
        .call("GET", &authority, Value::Null, Some(&f.admin_token))
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(terminal["revoked"], true);
    assert_eq!(terminal["policy"]["revision"], 5);
    assert_eq!(terminal["policy"]["policy_epoch"], 5);
    for path in [&rotate, &advance] {
        let (status, _) = f
            .call(
                "POST",
                path,
                json!({"expected_revision":5,"expected_policy_epoch":5}),
                Some(&f.admin_token),
            )
            .await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, _) = f
        .call(
            "PUT",
            &authority,
            json!({"expected_revision":5}),
            Some(&f.admin_token),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = f
        .call(
            "GET",
            &format!("{}/policy", f.base()),
            Value::Null,
            Some(&f.admin_token),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let probe = Connection::open(&f.database)?;
    let history:(u64,u64)=probe.query_row("SELECT count(*),sum(retired_at_ms IS NOT NULL) FROM network_authority_key_history WHERE space_id=?1",[&f.space],|r|Ok((r.get(0)?,r.get(1)?)))?;
    assert_eq!(history, (2, 2));
    Ok(())
}
