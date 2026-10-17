//! Strict TURN endpoint parsing and coturn REST credential primitives.
//!
//! Endpoint parsing prevents embedded credentials and ambiguous URI syntax. It
//! does not establish server identity or make an arbitrary endpoint trusted;
//! callers must obtain endpoints from trusted configuration or an allowlist.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::{net::Ipv6Addr, time::Duration};
use zeroize::{Zeroize, Zeroizing};

mod managed;
pub use managed::{
    TurnAction, TurnAllocationGrant, TurnAuthorization, TurnGrantError, TurnPeerActivation,
    TurnPeerBindingActivation, TurnPurpose,
};

type HmacSha1 = Hmac<Sha1>;

/// The shortest accepted credential lifetime.
pub const MIN_CREDENTIAL_LIFETIME: Duration = Duration::from_secs(60);
/// The longest accepted credential lifetime (15 minutes).
pub const MAX_CREDENTIAL_LIFETIME: Duration = Duration::from_secs(15 * 60);
const MAX_REST_SECRET_BYTES: usize = 1024;
const MAX_IDENTITY_BYTES: usize = 128;
const MAX_ENDPOINT_BYTES: usize = 2048;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TurnError {
    #[error("invalid TURN endpoint")]
    InvalidEndpoint,
    #[error("invalid coturn REST shared secret")]
    InvalidSecret,
    #[error("invalid coturn REST identity")]
    InvalidIdentity,
    #[error("credential lifetime must be a whole number of seconds between 60 and 900")]
    InvalidLifetime,
    #[error("credential expiry is outside the supported Unix timestamp range")]
    InvalidTimestamp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TurnTransport {
    Udp,
    Tcp,
}

/// A syntactically validated TURN endpoint without userinfo or URL fragments.
///
/// The endpoint must still come from an explicitly trusted configuration
/// source; parsing alone does not authenticate the remote server.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustedTurnEndpoint {
    uri: String,
    port: u16,
    secure: bool,
    transport: TurnTransport,
}

impl TrustedTurnEndpoint {
    pub fn parse(value: &str) -> Result<Self, TurnError> {
        if value.is_empty()
            || value.len() > MAX_ENDPOINT_BYTES
            || !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(TurnError::InvalidEndpoint);
        }

        let (scheme, authority_and_query) = if let Some(rest) = value.strip_prefix("turn:") {
            ("turn", rest)
        } else if let Some(rest) = value.strip_prefix("turns:") {
            ("turns", rest)
        } else {
            return Err(TurnError::InvalidEndpoint);
        };
        let secure = scheme == "turns";
        let (authority, query) = match authority_and_query.split_once('?') {
            Some((authority, query)) if !query.contains('?') => (authority, Some(query)),
            Some(_) => return Err(TurnError::InvalidEndpoint),
            None => (authority_and_query, None),
        };
        if authority.is_empty()
            || authority
                .bytes()
                .any(|byte| matches!(byte, b'@' | b'/' | b'\\' | b'#' | b'%'))
        {
            return Err(TurnError::InvalidEndpoint);
        }

        let (host, explicit_port) = parse_authority(authority)?;
        let port = explicit_port.unwrap_or(if secure { 5349 } else { 3478 });
        let transport = match query {
            None if secure => TurnTransport::Tcp,
            None => TurnTransport::Udp,
            Some("transport=udp") => TurnTransport::Udp,
            Some("transport=tcp") => TurnTransport::Tcp,
            Some(_) => return Err(TurnError::InvalidEndpoint),
        };
        if secure && transport != TurnTransport::Tcp {
            return Err(TurnError::InvalidEndpoint);
        }

        let mut uri = format!("{scheme}:{host}");
        if let Some(port) = explicit_port {
            uri.push(':');
            uri.push_str(&port.to_string());
        }
        if let Some(query) = query {
            uri.push('?');
            uri.push_str(query);
        }

        Ok(Self {
            uri,
            port,
            secure,
            transport,
        })
    }

    /// The normalized TURN URI, with no credentials.
    pub fn as_uri(&self) -> &str {
        &self.uri
    }

    /// The configured or scheme-default port.
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_secure(&self) -> bool {
        self.secure
    }

    pub fn transport(&self) -> TurnTransport {
        self.transport
    }
}

fn parse_authority(authority: &str) -> Result<(String, Option<u16>), TurnError> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (address, suffix) = bracketed
            .split_once(']')
            .ok_or(TurnError::InvalidEndpoint)?;
        let address = address
            .parse::<Ipv6Addr>()
            .map_err(|_| TurnError::InvalidEndpoint)?;
        if address.is_unspecified() || address.is_multicast() {
            return Err(TurnError::InvalidEndpoint);
        }
        let port = if suffix.is_empty() {
            None
        } else {
            Some(parse_port(
                suffix.strip_prefix(':').ok_or(TurnError::InvalidEndpoint)?,
            )?)
        };
        return Ok((format!("[{address}]"), port));
    }

    if authority.matches(':').count() > 1 {
        return Err(TurnError::InvalidEndpoint);
    }
    let (raw_host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(parse_port(port)?)),
        None => (authority, None),
    };
    if raw_host.is_empty() {
        return Err(TurnError::InvalidEndpoint);
    }

    let host = match raw_host.parse::<std::net::Ipv4Addr>() {
        Ok(address) if !address.is_unspecified() && !address.is_multicast() => address.to_string(),
        Ok(_) => return Err(TurnError::InvalidEndpoint),
        Err(_) if valid_dns_name(raw_host) => raw_host.to_ascii_lowercase(),
        Err(_) => return Err(TurnError::InvalidEndpoint),
    };
    Ok((host, port))
}

fn parse_port(value: &str) -> Result<u16, TurnError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TurnError::InvalidEndpoint);
    }
    let port = value
        .parse::<u16>()
        .map_err(|_| TurnError::InvalidEndpoint)?;
    if port == 0 {
        return Err(TurnError::InvalidEndpoint);
    }
    Ok(port)
}

fn valid_dns_name(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 253
        || value.ends_with('.')
        || value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

/// An owned coturn REST shared secret that is cleared when dropped.
pub struct CoturnRestSecret(Zeroizing<Vec<u8>>);

impl CoturnRestSecret {
    /// Takes ownership of secret bytes and zeroizes them on drop.
    pub fn from_bytes(secret: Vec<u8>) -> Result<Self, TurnError> {
        let secret = Zeroizing::new(secret);
        if secret.is_empty() || secret.len() > MAX_REST_SECRET_BYTES {
            return Err(TurnError::InvalidSecret);
        }
        Ok(Self(secret))
    }

    /// Takes ownership of a text secret and zeroizes its allocation on drop.
    pub fn from_string(secret: String) -> Result<Self, TurnError> {
        Self::from_bytes(secret.into_bytes())
    }
}

/// The username and HMAC password returned by coturn's REST authentication.
/// Both strings are cleared when this value is dropped.
pub struct CoturnRestCredentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    expires_at_unix: u64,
}

impl CoturnRestCredentials {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

/// Issues short-lived coturn REST credentials using `expiry:identity` and
/// `Base64(HMAC-SHA1(shared_secret, username))`.
pub fn issue_coturn_rest_credentials(
    secret: &CoturnRestSecret,
    identity: &str,
    lifetime: Duration,
) -> Result<CoturnRestCredentials, TurnError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TurnError::InvalidTimestamp)?
        .as_secs();
    issue_coturn_rest_credentials_at(secret, identity, lifetime, now)
}

fn issue_coturn_rest_credentials_at(
    secret: &CoturnRestSecret,
    identity: &str,
    lifetime: Duration,
    now_unix: u64,
) -> Result<CoturnRestCredentials, TurnError> {
    if !valid_identity(identity) {
        return Err(TurnError::InvalidIdentity);
    }
    if lifetime.subsec_nanos() != 0
        || !(MIN_CREDENTIAL_LIFETIME..=MAX_CREDENTIAL_LIFETIME).contains(&lifetime)
    {
        return Err(TurnError::InvalidLifetime);
    }
    let expires_at_unix = now_unix
        .checked_add(lifetime.as_secs())
        .filter(|expiry| *expiry <= i64::MAX as u64)
        .ok_or(TurnError::InvalidTimestamp)?;
    let username = Zeroizing::new(format!("{expires_at_unix}:{identity}"));
    let mut mac = HmacSha1::new_from_slice(&secret.0).map_err(|_| TurnError::InvalidSecret)?;
    mac.update(username.as_bytes());
    let mut digest = mac.finalize().into_bytes();
    let password = Zeroizing::new(STANDARD.encode(digest.as_slice()));
    digest.as_mut_slice().zeroize();

    Ok(CoturnRestCredentials {
        username,
        password,
        expires_at_unix,
    })
}

fn valid_identity(identity: &str) -> bool {
    !identity.is_empty()
        && identity.len() <= MAX_IDENTITY_BYTES
        && identity
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_and_normalizes_strict_turn_endpoints() -> Result<(), TurnError> {
        let udp = TrustedTurnEndpoint::parse("turn:Relay.Example.net:3478?transport=udp")?;
        assert_eq!(udp.as_uri(), "turn:relay.example.net:3478?transport=udp");
        assert_eq!(udp.port(), 3478);
        assert!(!udp.is_secure());
        assert_eq!(udp.transport(), TurnTransport::Udp);

        let tls = TrustedTurnEndpoint::parse("turns:[2001:db8::1]?transport=tcp")?;
        assert_eq!(tls.as_uri(), "turns:[2001:db8::1]?transport=tcp");
        assert_eq!(tls.port(), 5349);
        assert!(tls.is_secure());
        assert_eq!(tls.transport(), TurnTransport::Tcp);

        let defaults = TrustedTurnEndpoint::parse("turn:relay.example.net")?;
        assert_eq!(defaults.port(), 3478);
        assert_eq!(defaults.transport(), TurnTransport::Udp);
        Ok(())
    }

    #[test]
    fn rejects_ambiguous_or_untrusted_turn_endpoint_syntax() {
        for input in [
            "stun:relay.example.net",
            "TURN:relay.example.net",
            "turn:",
            "turn:user@relay.example.net",
            "turn:user:pass@relay.example.net:3478",
            "turn:relay.example.net/path",
            "turn:relay.example.net#fragment",
            "turn:relay.example.net?transport=ws",
            "turns:relay.example.net?transport=udp",
            "turn:relay.example.net?transport=udp&transport=tcp",
            "turn:relay.example.net?transport=udp?x=y",
            "turn:relay.example.net:",
            "turn:relay.example.net:0",
            "turn:relay.example.net:65536",
            "turn:relay.example.net:3478x",
            "turn:2001:db8::1",
            "turn:[2001:db8::1",
            "turn:[::]:3478",
            "turn:0.0.0.0:3478",
            "turn:999.1.1.1",
            "turn:127.0.0.1.",
            "turn:relay..example.net",
            "turn:relay.example.net%2f.evil",
            "turn: relay.example.net",
            "turn:例子.测试",
        ] {
            assert!(
                TrustedTurnEndpoint::parse(input).is_err(),
                "unexpectedly accepted {input:?}"
            );
        }
    }

    #[test]
    fn coturn_rest_credentials_match_independent_fixed_hmac_vector() -> Result<(), TurnError> {
        // Independently generated with Python's stdlib hmac/hashlib:
        // Base64(HMAC-SHA1(b"secret", b"1700000900:alice"))
        // = XmP8DHyYA0lSzVc7ZGNOsYRGEwE=
        let secret = CoturnRestSecret::from_string("secret".to_owned())?;
        let credentials = issue_coturn_rest_credentials_at(
            &secret,
            "alice",
            Duration::from_secs(900),
            1_700_000_000,
        )?;
        assert_eq!(credentials.username(), "1700000900:alice");
        assert_eq!(credentials.password(), "XmP8DHyYA0lSzVc7ZGNOsYRGEwE=");
        assert_eq!(credentials.expires_at_unix(), 1_700_000_900);
        Ok(())
    }

    #[test]
    fn credential_lifetimes_and_identities_are_hard_bounded() -> Result<(), TurnError> {
        let secret = CoturnRestSecret::from_bytes(b"secret".to_vec())?;
        let minimum = issue_coturn_rest_credentials_at(
            &secret,
            "alice",
            MIN_CREDENTIAL_LIFETIME,
            1_700_000_000,
        )?;
        assert_eq!(minimum.expires_at_unix(), 1_700_000_060);
        let maximum = issue_coturn_rest_credentials_at(
            &secret,
            "alice",
            MAX_CREDENTIAL_LIFETIME,
            1_700_000_000,
        )?;
        assert_eq!(maximum.expires_at_unix(), 1_700_000_900);
        for lifetime in [
            Duration::ZERO,
            Duration::from_secs(59),
            Duration::from_secs(901),
            Duration::from_millis(60_001),
        ] {
            assert!(matches!(
                issue_coturn_rest_credentials_at(&secret, "alice", lifetime, 1_700_000_000),
                Err(TurnError::InvalidLifetime)
            ));
        }
        let long_identity = "x".repeat(129);
        for identity in [
            "",
            "alice:admin",
            "alice@example.net",
            long_identity.as_str(),
            "身份",
        ] {
            assert!(matches!(
                issue_coturn_rest_credentials_at(
                    &secret,
                    identity,
                    Duration::from_secs(60),
                    1_700_000_000
                ),
                Err(TurnError::InvalidIdentity)
            ));
        }
        assert!(matches!(
            issue_coturn_rest_credentials_at(
                &secret,
                "alice",
                Duration::from_secs(60),
                i64::MAX as u64
            ),
            Err(TurnError::InvalidTimestamp)
        ));
        Ok(())
    }

    #[test]
    fn shared_secrets_must_be_nonempty_and_bounded() {
        assert!(matches!(
            CoturnRestSecret::from_bytes(Vec::new()),
            Err(TurnError::InvalidSecret)
        ));
        assert!(matches!(
            CoturnRestSecret::from_bytes(vec![0; MAX_REST_SECRET_BYTES + 1]),
            Err(TurnError::InvalidSecret)
        ));
    }
}
