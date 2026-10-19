use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use nestlink_auth::{VaultKey, random_id};
use nestlink_identity::PermitSigner;
use nestlink_server::{AppState, router};
use nestlink_storage::Store;
use serde_json::{Value, json};
use tower::ServiceExt;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::test]
async fn unauthenticated_random_bearers_do_not_consume_login_capacity() -> Result {
    let app = app()?;
    for index in 0..2100 {
        let token = format!("{index:043}");
        let (status, _) = call(
            &app,
            "PUT",
            "/api/v3/auth/password",
            json!({}),
            Some(&token),
        )
        .await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = call(
        &app,
        "POST",
        "/api/v3/auth/login",
        json!({"username":"admin","password":"http-only-test-password"}),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn http_restore_requires_exact_origin_and_the_selected_httponly_slot() -> Result {
    let app = app()?;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v3/auth/login")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({"username":"admin","password":"http-only-test-password"}).to_string(),
                ))?,
        )
        .await?;
    let cookies: Vec<_> = response
        .headers()
        .get_all("Set-Cookie")
        .iter()
        .map(|value| value.to_str().map(str::to_owned))
        .collect::<std::result::Result<_, _>>()?;
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 262144).await?)?;
    let selected = body["principal"]["session_id"]
        .as_str()
        .ok_or("missing session")?;
    let cookie = cookies
        .iter()
        .find(|cookie| cookie.starts_with(&format!("nl15_restore_{selected}=")))
        .ok_or("missing restore slot")?
        .split(';')
        .next()
        .ok_or("missing cookie")?;
    for (origin, status) in [
        (None, StatusCode::FORBIDDEN),
        (Some("https://other.example.test"), StatusCode::FORBIDDEN),
        (Some("https://console.example.test"), StatusCode::OK),
    ] {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/api/v3/auth/restore")
            .header("Content-Type", "application/json")
            .header("Cookie", cookie);
        if let Some(origin) = origin {
            builder = builder.header("Origin", origin);
        }
        let response = app
            .clone()
            .oneshot(builder.body(Body::from(json!({"session_id":selected}).to_string()))?)
            .await?;
        assert_eq!(response.status(), status);
        if status == StatusCode::OK {
            let restored: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 262144).await?)?;
            assert_eq!(restored["principal"]["session_id"], selected);
        }
    }
    Ok(())
}
fn app() -> Result<Router> {
    let mut store = Store::in_memory(&random_id())?;
    store.bootstrap_admin("admin", "http-only-test-password")?;
    Ok(router(AppState::new(
        store,
        VaultKey::from_bytes([4; 32]),
        PermitSigner::generate(),
        "https://console.example.test".into(),
        true,
    )?))
}
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    body: Value,
    token: Option<&str>,
) -> Result<(StatusCode, Value)> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("Content-Type", "application/json");
    if let Some(token) = token {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(serde_json::to_vec(&body)?))?)
        .await?;
    let status = response.status();
    assert_eq!(
        response
            .headers()
            .get("Cache-Control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let bytes = to_bytes(response.into_body(), 262144).await?;
    Ok((
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        },
    ))
}
#[tokio::test]
async fn login_cookie_scope_refresh_logout_and_legacy_rejection() -> Result {
    let app = app()?;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v3/auth/login")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({"username":"admin","password":"http-only-test-password"}).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let cookies: Vec<_> = response
        .headers()
        .get_all("Set-Cookie")
        .iter()
        .map(|v| v.to_str())
        .collect::<std::result::Result<_, _>>()?;
    assert_eq!(cookies.len(), 3);
    for cookie in cookies {
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/api/v3"));
        assert!(!cookie.contains("Domain="));
    }
    let grant: Value = serde_json::from_slice(&to_bytes(response.into_body(), 262144).await?)?;
    let token = grant["access_token"]
        .as_str()
        .ok_or("missing access token")?;
    assert_eq!(
        call(&app, "GET", "/api/v3/auth/me", Value::Null, Some(token))
            .await?
            .0,
        StatusCode::OK
    );
    let refresh_body =
        json!({"refresh_token":grant["refresh_token"],"generation":grant["generation"]});
    let (status, next) = call(
        &app,
        "POST",
        "/api/v3/auth/refresh",
        refresh_body.clone(),
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        call(&app, "POST", "/api/v3/auth/refresh", refresh_body, None)
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "GET", "/api/v3/auth/me", Value::Null, Some(token))
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    let token = next["access_token"]
        .as_str()
        .ok_or("missing refreshed token")?;
    assert_eq!(
        call(
            &app,
            "POST",
            "/api/v3/auth/logout",
            Value::Null,
            Some(token)
        )
        .await?
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, "GET", "/api/v3/auth/me", Value::Null, Some(token))
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "POST", "/api/v2/login", Value::Null, None)
            .await?
            .0,
        StatusCode::NOT_FOUND
    );
    Ok(())
}
#[tokio::test]
async fn csrf_foreign_origin_and_oversized_body_are_rejected() -> Result {
    let app = app()?;
    for (cookie, origin) in [
        (
            Some("nl15_access=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            None,
        ),
        (None, Some("https://attacker.example")),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/api/v3/auth/login")
            .header("Content-Type", "application/json");
        if let Some(cookie) = cookie {
            request = request.header("Cookie", cookie);
        }
        if let Some(origin) = origin {
            request = request.header("Origin", origin);
        }
        let response = app.clone().oneshot(request.body(Body::from("{}"))?).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v3/auth/login")
                .header("Content-Type", "application/json")
                .body(Body::from("x".repeat(262145)))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}
