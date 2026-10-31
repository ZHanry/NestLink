use super::*;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn session() -> BrowserSession {
    let (stopped, _) = watch::channel(false);
    BrowserSession {
        cookie_hash: [4; 32],
        stopped,
        cookies: Jar::default(),
        cookie_bytes: AtomicUsize::new(0),
    }
}
fn gateway() -> Result<Url> {
    Ok(Url::parse("https://service.private.example.net/")?)
}
fn target() -> Result<Url> {
    Ok(Url::parse("http://approved.internal/")?)
}

#[test]
fn isolated_origin_refuses_management_parent_cookie_scope_and_noncanonical_urls() -> Result {
    let manager = Url::parse("https://control.example.com/")?;
    for value in [
        "https://service.private.example.com",
        "https://control.example.com",
        "http://service.other.net",
        "https://service.other.net:444",
        "https://service.other.net/path",
        "https://127.0.0.1",
        "https://SERVICE.other.net",
    ] {
        assert!(origin(value, &manager).is_err(), "{value}");
    }
    assert!(origin("https://service.private.example.net", &manager).is_ok());
    Ok(())
}
#[test]
fn private_hop_host_sni_and_single_session_cookie_are_exact() -> Result {
    let hop = token();
    let hash = token_hash("private-web-hop", hop.expose());
    let mut request = Request::builder()
        .uri("/app?url=http://untrusted.invalid")
        .header("Host", "service.private.example.net")
        .header("X-NestLink-Token", hop.expose())
        .header("X-NestLink-Scheme", "https")
        .header("X-NestLink-SNI", "service.private.example.net")
        .body(())?;
    assert!(authenticate(&request, &gateway()?, &hash).is_ok());
    request.headers_mut().insert(
        "x-nestlink-sni",
        HeaderValue::from_static("control.example.com"),
    );
    assert!(authenticate(&request, &gateway()?, &hash).is_err());
    request.headers_mut().insert(
        header::COOKIE,
        format!("{SESSION_COOKIE}={}; other=ignored", hop.expose()).parse()?,
    );
    assert_eq!(session_cookie(request.headers()), Some(hop.expose()));
    request.headers_mut().append(
        header::COOKIE,
        format!("{SESSION_COOKIE}={}", hop.expose()).parse()?,
    );
    assert!(session_cookie(request.headers()).is_none());
    Ok(())
}
#[test]
fn browser_cookies_never_reach_target_and_application_cookies_never_reach_browser() -> Result {
    let session = session();
    let mut response = HeaderMap::new();
    response.append(
        header::SET_COOKIE,
        HeaderValue::from_static("login=approved; Path=/; HttpOnly"),
    );
    response.append(
        header::SET_COOKIE,
        HeaderValue::from_static("nl15_access=forged; Domain=example.com; Path=/api/v3"),
    );
    application_response(&mut response, &gateway()?, &target()?, &session, false)?;
    assert!(!response.contains_key(header::SET_COOKIE));
    let mut request = Request::builder()
        .method("POST")
        .uri("/form")
        .header("Origin", "https://service.private.example.net")
        .header("Cookie", "nl15_access=browser; application=from-sibling")
        .header("Authorization", "Bearer do-not-forward")
        .header("X-Forwarded-Host", "untrusted.invalid")
        .body(())?;
    assert!(!application_request(
        &mut request,
        &gateway()?,
        &target()?,
        &session
    )?);
    assert_eq!(
        request.headers().get(header::HOST).ok_or("Host missing")?,
        "approved.internal"
    );
    assert_eq!(
        request
            .headers()
            .get(header::ORIGIN)
            .ok_or("Origin missing")?,
        "http://approved.internal"
    );
    assert_eq!(
        request
            .headers()
            .get(header::COOKIE)
            .ok_or("backend cookie missing")?,
        "login=approved"
    );
    assert!(!request.headers().contains_key(header::AUTHORIZATION));
    assert!(!request.headers().contains_key("x-forwarded-host"));
    Ok(())
}
#[test]
fn unsafe_requests_and_websocket_upgrades_require_exact_origin() -> Result {
    for (method, source, upgrade) in [
        ("POST", None, false),
        ("POST", Some("https://control.example.com"), false),
        ("GET", None, true),
        ("GET", Some("https://sibling.private.example.net"), true),
    ] {
        let mut request = Request::builder().method(method).uri("/socket").body(())?;
        if let Some(source) = source {
            request
                .headers_mut()
                .insert(header::ORIGIN, source.parse()?);
        }
        if upgrade {
            request
                .headers_mut()
                .insert(header::UPGRADE, "websocket".parse()?);
            request
                .headers_mut()
                .insert(header::CONNECTION, "Upgrade".parse()?);
        }
        assert!(application_request(&mut request, &gateway()?, &target()?, &session()).is_err());
    }
    let mut request = Request::builder()
        .uri("/socket")
        .header("Origin", "https://service.private.example.net")
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .body(())?;
    assert!(application_request(
        &mut request,
        &gateway()?,
        &target()?,
        &session()
    )?);
    Ok(())
}
#[test]
fn redirects_never_choose_another_origin_or_gateway_control_route() -> Result {
    for location in [
        "https://untrusted.invalid/",
        "//untrusted.invalid/",
        "/.nestlink/session",
        "http://user:password@approved.internal/",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::LOCATION, location.parse()?);
        assert!(
            application_response(&mut headers, &gateway()?, &target()?, &session(), false).is_err(),
            "{location}"
        );
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::LOCATION, "/next?x=1#item".parse()?);
    application_response(&mut headers, &gateway()?, &target()?, &session(), false)?;
    assert_eq!(
        headers.get(header::LOCATION).ok_or("redirect missing")?,
        "https://service.private.example.net/next?x=1#item"
    );
    Ok(())
}
#[test]
fn application_cookie_storage_has_a_finite_lifetime_byte_budget() -> Result {
    let session = session();
    session.cookie_bytes.store(COOKIE_BYTES, Ordering::Release);
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, "another=value".parse()?);
    assert!(application_response(&mut headers, &gateway()?, &target()?, &session, false).is_err());
    Ok(())
}

#[test]
fn application_paths_cannot_change_the_original_backend_cookie_origin() -> Result {
    let backend = target()?;
    for path in [
        "//untrusted.invalid/",
        r"/\untrusted.invalid/",
        "http://untrusted.invalid/",
        "https://approved.internal/",
        "http://approved.internal:444/",
        "http://user@approved.internal/",
    ] {
        assert!(application_url(&backend, path).is_err(), "{path}");
    }
    let fixed = application_url(&backend, "/page?next=https://untrusted.invalid/")?;
    assert_eq!(fixed.origin(), backend.origin());
    assert_eq!(fixed.host_str(), Some("approved.internal"));
    for path in ["//untrusted.invalid/", r"/\untrusted.invalid/"] {
        let request = Request::builder()
            .uri(path)
            .header("Sec-Fetch-Site", "same-origin")
            .body(());
        // A URI rejected by Hyper's parser never reaches the cookie adapter.
        if let Ok(mut request) = request {
            assert!(
                application_request(&mut request, &gateway()?, &backend, &session()).is_err(),
                "{path}"
            );
        }
    }
    Ok(())
}
