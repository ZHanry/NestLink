use super::*;

#[tokio::test]
async fn management_login_export_round_trip_preserves_an_accepted_origin()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let issuer = nestlink_identity::PermitSigner::generate().public_key();
    let deployment_id = random_id();
    let origin = "https://control.example.test:8443";
    let mut sdk = Sdk {
        client: Client::builder().no_proxy().build()?,
        origin: parse_origin(origin, false)?,
        trust: DeploymentTrust {
            deployment_id: deployment_id.clone(),
            permit_issuer: issuer,
        },
        health: HealthResponse {
            product: "NestLink".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            api_base: API_BASE.into(),
            alpn: ALPN.into(),
            deployment_id,
            security_epoch: 1,
            permit_issuer: URL_SAFE_NO_PAD.encode(issuer),
            node_policy_issuer: URL_SAFE_NO_PAD.encode(issuer),
            native_ice_version: 0,
        },
        login: None,
    };
    sdk.install_login(LoginResponse {
        principal: Principal {
            account_id: random_id(),
            session_id: random_id(),
            name: "recovery-test".into(),
            is_admin: false,
            access_expires: 9999999999,
        },
        access_token: "A".repeat(43),
        refresh_token: "B".repeat(43),
        refresh_expires: 9999999999,
        generation: 7,
    })?;
    assert_eq!(sdk.management_origin(), origin);
    let exported = sdk.export_login()?.ok_or("missing saved login")?;
    let saved: serde_json::Value = serde_json::from_slice(&exported)?;
    let exported_origin = saved["origin"].as_str().ok_or("missing origin")?;
    assert_eq!(exported_origin, origin);
    assert!(parse_origin(exported_origin, false).is_ok());
    assert_eq!(saved_management_origin(exported_origin)?, origin);
    assert_eq!(saved["deployment_id"], sdk.trust.deployment_id);
    assert_eq!(saved["login"]["generation"], 7);
    assert_eq!(saved["login"]["refresh_token"], "B".repeat(43));
    Ok(())
}

#[test]
fn management_login_legacy_root_slash_is_migrated_without_widening_origin_validation()
-> Result<(), SdkError> {
    for origin in [
        "https://control.example.test",
        "https://control.example.test:8443",
        "https://[2001:db8::1]:8443",
    ] {
        assert_eq!(saved_management_origin(origin)?, origin);
        assert_eq!(saved_management_origin(&format!("{origin}/"))?, origin);
    }
    for invalid in [
        "http://control.example.test/",
        "http://127.0.0.1/",
        "https://user@control.example.test/",
        "https://control.example.test/path/",
        "https://control.example.test//",
        "https://control.example.test/./",
        "https://control.example.test/?key=1",
        "https://control.example.test/#fragment",
        "https://CONTROL.example.test/",
        "https://control.example.test:443/",
        "https://control.example.test/ ",
    ] {
        assert!(matches!(
            saved_management_origin(invalid),
            Err(SdkError::Invalid)
        ));
    }
    // Interactive callers retain the original strict input contract.
    assert!(parse_origin("https://control.example.test/", false).is_err());
    Ok(())
}
