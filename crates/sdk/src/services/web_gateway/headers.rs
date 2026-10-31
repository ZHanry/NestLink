//! Policy around Hyper's mature framing and reqwest's mature cookie storage.
use super::*;
use hyper::{
    Method, Uri,
    header::{self, HeaderMap, HeaderName, HeaderValue},
};
use nestlink_protocol::api::ServiceIngress;
use reqwest::cookie::CookieStore;
use std::sync::atomic::Ordering;

const COOKIE_BYTES: usize = 64 * 1024;
pub(super) const LAUNCH_PAGE: &str = r#"<!doctype html><html><head><meta charset="utf-8"><title>Open private service</title></head><body><p id="status">Opening the authorized private service…</p><script>
const ticket=location.hash.slice(1);history.replaceState(null,'','/.nestlink/launch');
if(!/^[A-Za-z0-9_-]{43}$/.test(ticket)){document.getElementById('status').textContent='This private service link is missing or expired.';}
else fetch('/.nestlink/session',{method:'POST',credentials:'same-origin',redirect:'error',headers:{Authorization:'NestLinkTicket '+ticket}}).then(r=>{if(!r.ok)throw Error();location.replace('/');}).catch(()=>{document.getElementById('status').textContent='This private service link is missing, already used or expired.';});
</script></body></html>"#;

pub(super) fn origin(value: &str, management: &Url) -> Result<Url, SdkError> {
    super::super::web_launch::isolated_origin(value.strip_suffix('/').unwrap_or(value), management)
}
pub(super) fn backend(ingress: &ServiceIngress) -> Result<Url, SdkError> {
    let value = match ingress {
        ServiceIngress::Http { hostname } => format!("http://{hostname}/"),
        ServiceIngress::Https { hostname } => format!("https://{hostname}/"),
        _ => return Err(SdkError::Invalid),
    };
    Url::parse(&value).map_err(|_| SdkError::Invalid)
}
fn denied() -> io::Error {
    io::Error::other("private web boundary refused")
}
pub(super) fn application_url(backend: &Url, path: &str) -> io::Result<Url> {
    let url = backend.join(path).map_err(|_| denied())?;
    if url.origin() != backend.origin() || !url.username().is_empty() || url.password().is_some() {
        return Err(denied());
    }
    Ok(url)
}
fn one<'a>(headers: &'a HeaderMap, name: &str) -> io::Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .map(|value| value.to_str().map_err(|_| denied()))
        .transpose()?;
    if values.next().is_some() {
        return Err(denied());
    }
    Ok(value)
}
pub(super) fn authenticate<B>(
    request: &Request<B>,
    origin: &Url,
    hop: &[u8; 32],
) -> io::Result<()> {
    let headers = request.headers();
    let size = headers.iter().try_fold(0usize, |total, (name, value)| {
        total
            .checked_add(name.as_str().len() + value.len() + 4)
            .ok_or_else(denied)
    })?;
    let host = origin.host_str().ok_or_else(denied)?;
    let supplied = one(headers, "x-nestlink-token")?.ok_or_else(denied)?;
    if size > 32768
        || headers.len() > 128
        || !matches!(one(headers,"host")?,Some(value) if value==host || value==format!("{host}:443"))
        || one(headers, "x-nestlink-scheme")? != Some("https")
        || one(headers, "x-nestlink-sni")? != Some(host)
        || supplied.len() != 43
        || token_hash("private-web-hop", supplied) != *hop
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || !request.uri().path().starts_with('/')
        || request.method() == Method::CONNECT
        || request.method() == Method::TRACE
    {
        return Err(denied());
    }
    Ok(())
}
pub(super) fn same_origin(headers: &HeaderMap, origin: &Url) -> bool {
    one(headers, "origin").ok().flatten() == Some(origin.origin().ascii_serialization().as_str())
}
fn opaque(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
pub(super) fn launch_ticket(headers: &HeaderMap) -> Option<&str> {
    one(headers, "authorization")
        .ok()
        .flatten()?
        .strip_prefix("NestLinkTicket ")
        .filter(|value| opaque(value))
}
pub(super) fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    let cookies = one(headers, "cookie").ok().flatten()?;
    let mut matched = None;
    for part in cookies.split(';') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        if name == SESSION_COOKIE {
            if matched.is_some() || !opaque(value) {
                return None;
            }
            matched = Some(value);
        }
    }
    matched
}
fn websocket(headers: &HeaderMap) -> io::Result<bool> {
    match one(headers, "upgrade")? {
        None => Ok(false),
        Some(value)
            if value.eq_ignore_ascii_case("websocket")
                && one(headers, "connection")?.is_some_and(|value| {
                    value
                        .split(',')
                        .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
                }) =>
        {
            Ok(true)
        }
        _ => Err(denied()),
    }
}
fn remove_hop(headers: &mut HeaderMap, upgrade: bool) {
    let nominated: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| value.trim().parse().ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
    ] {
        headers.remove(name);
    }
    let internal: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            name.as_str().starts_with("x-nestlink-") || name.as_str().starts_with("access-control-")
        })
        .cloned()
        .collect();
    for name in internal {
        headers.remove(name);
    }
    if upgrade {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    } else {
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
}
pub(super) fn application_request<B>(
    request: &mut Request<B>,
    origin: &Url,
    backend: &Url,
    session: &BrowserSession,
) -> io::Result<bool> {
    let upgrade = websocket(request.headers())?;
    let source = one(request.headers(), "origin")?;
    let fetch = one(request.headers(), "sec-fetch-site")?;
    if one(request.headers(), "content-length")?.is_some()
        && one(request.headers(), "transfer-encoding")?.is_some()
    {
        return Err(denied());
    }
    if source.is_some() && !same_origin(request.headers(), origin)
        || source.is_none() && fetch.is_none()
        || (upgrade
            || !matches!(
                *request.method(),
                Method::GET | Method::HEAD | Method::OPTIONS
            ))
            && !same_origin(request.headers(), origin)
        || fetch.is_some_and(|site| !matches!(site, "same-origin" | "none"))
    {
        return Err(denied());
    }
    let had_origin = source.is_some();
    let path = request
        .uri()
        .path_and_query()
        .ok_or_else(denied)?
        .as_str()
        .parse::<Uri>()
        .map_err(|_| denied())?;
    // Keep an origin-form URI. Hyper never resolves or dials this value.
    *request.uri_mut() = path;
    let headers = request.headers_mut();
    remove_hop(headers, upgrade);
    headers.remove(header::AUTHORIZATION);
    headers.remove(header::COOKIE);
    headers.remove(header::REFERER);
    headers.insert(
        header::HOST,
        HeaderValue::from_str(backend.host_str().ok_or_else(denied)?).map_err(|_| denied())?,
    );
    if had_origin {
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_str(&backend.origin().ascii_serialization()).map_err(|_| denied())?,
        );
    }
    let cookie_url = application_url(
        backend,
        request.uri().path_and_query().ok_or_else(denied)?.as_str(),
    )?;
    if let Some(cookie) = session.cookies.cookies(&cookie_url) {
        request.headers_mut().insert(header::COOKIE, cookie);
    }
    Ok(upgrade)
}
pub(super) fn browser_response(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.append("content-security-policy",HeaderValue::from_static("default-src 'self' data: blob:; script-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; frame-src 'none'; object-src 'none'; worker-src 'none'; base-uri 'self'"));
}
pub(super) fn application_response(
    headers: &mut HeaderMap,
    origin: &Url,
    backend: &Url,
    session: &BrowserSession,
    upgrade: bool,
) -> io::Result<()> {
    let bytes = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .try_fold(0usize, |sum, value| {
            sum.checked_add(value.len()).ok_or_else(denied)
        })?;
    session
        .cookie_bytes
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |total| {
            total
                .checked_add(bytes)
                .filter(|next| *next <= COOKIE_BYTES)
        })
        .map_err(|_| denied())?;
    // A separate mature Jar is owned by exactly this browser session/service.
    // No application Cookie or Set-Cookie crosses into the browser cookie store.
    session
        .cookies
        .set_cookies(&mut headers.get_all(header::SET_COOKIE).iter(), backend);
    headers.remove(header::SET_COOKIE);
    if let Some(value) = one(headers, "location")? {
        let location = backend.join(value).map_err(|_| denied())?;
        if location.origin() != backend.origin()
            || !location.username().is_empty()
            || location.password().is_some()
            || location.path().starts_with("/.nestlink/")
        {
            return Err(denied());
        }
        let mut rewritten = origin.clone();
        rewritten.set_path(location.path());
        rewritten.set_query(location.query());
        rewritten.set_fragment(location.fragment());
        headers.insert(
            header::LOCATION,
            HeaderValue::from_str(rewritten.as_str()).map_err(|_| denied())?,
        );
    }
    for name in [
        "refresh",
        "content-location",
        "service-worker-allowed",
        "clear-site-data",
        "alt-svc",
    ] {
        headers.remove(name);
    }
    remove_hop(headers, upgrade);
    browser_response(headers);
    Ok(())
}

#[cfg(test)]
mod tests;
