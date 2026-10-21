//! A browser-only WebRTC controller peer. Trust decisions stay outside SDP:
//! callers provide a verified permit, the just-registered browser identity and
//! a trusted deployment ICE configuration. Remote signaling always goes
//! through the SDK's signed-signal verifier.

#[cfg(target_arch = "wasm32")]
use nestlink_identity::VerifiedPermit;
#[cfg(any(target_arch = "wasm32", test))]
use nestlink_protocol::Path;
#[cfg(target_arch = "wasm32")]
use nestlink_protocol::api::BrowserEndpointLease;
#[cfg(target_arch = "wasm32")]
use nestlink_sdk::DeviceIdentity;
#[cfg(target_arch = "wasm32")]
use std::{cell::Cell, rc::Rc};
use zeroize::Zeroize;

const MAX_ICE_SERVERS: usize = 16;
const MAX_ICE_URLS_PER_SERVER: usize = 8;
const MAX_ICE_URL_BYTES: usize = 512;
const MAX_TURN_USERNAME_BYTES: usize = 256;
const MAX_TURN_CREDENTIAL_BYTES: usize = 1024;
#[cfg(target_arch = "wasm32")]
const MAX_OPERATION_MS: u32 = 30_000;
#[cfg(target_arch = "wasm32")]
const ICE_GATHER_TIMEOUT_MS: u32 = 15_000;
#[cfg(target_arch = "wasm32")]
const POLL_INTERVAL_MS: u32 = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerPathMode {
    DirectOnly,
    DirectPreferred,
    RelayOnly,
}

impl PeerPathMode {
    pub fn parse(value: &str) -> Result<Self, PeerError> {
        match value {
            "direct_only" => Ok(Self::DirectOnly),
            "direct_preferred" => Ok(Self::DirectPreferred),
            "relay_only" => Ok(Self::RelayOnly),
            _ => Err(PeerError::InvalidPathMode),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedPath {
    Direct,
    Relay,
    Mixed,
}

/// Only connectivity transitions require an ICE restart. Network Information
/// `change` events describe throughput estimates (such as `effectiveType`) and
/// can be caused by congestion or page-scoped throttling while the route stays
/// valid.
pub fn network_event_requires_ice_restart(event_type: &str) -> bool {
    matches!(event_type, "online" | "offline")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerError {
    InvalidIceConfiguration,
    InvalidPathMode,
    InvalidPermit,
    EndpointMismatch,
    EndpointLeaseExpired,
    UnauthorizedTrack,
    CodecUnavailable,
    PathNotPermitted,
    RelayUnavailable,
    NoSelectedPath,
    SelectedPathRejected,
    OfferRequired,
    AnswerRequired,
    UnsupportedTrickleSignal,
    Cancelled,
    Expired,
    TimedOut,
    BrowserUnavailable,
    BrowserOperation,
    SignalRejected,
    ManagementFailure(nestlink_protocol::diagnostics::ConnectionFailure),
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidIceConfiguration => "trusted ICE configuration is invalid",
            Self::InvalidPathMode => "path mode is invalid",
            Self::InvalidPermit => "permit is invalid or expired",
            Self::EndpointMismatch => "browser identity is not the permitted controller",
            Self::EndpointLeaseExpired => "temporary browser endpoint lease is expired",
            Self::UnauthorizedTrack => "remote media track was not approved",
            Self::CodecUnavailable => "VP8/Opus media profile is unavailable",
            Self::PathNotPermitted => "the permitted session does not allow the required path",
            Self::RelayUnavailable => "an authorized TURN relay is unavailable for this connection",
            Self::NoSelectedPath => "the browser did not report a selected ICE candidate pair",
            Self::SelectedPathRejected => "the selected ICE candidate pair violates the path mode",
            Self::OfferRequired => "create and publish an offer before receiving an answer",
            Self::AnswerRequired => "the browser controller requires a signed SDP answer",
            Self::UnsupportedTrickleSignal => {
                "candidate-only signaling is unsupported; a signed SDP description is required"
            }
            Self::Cancelled => "the browser peer was cancelled",
            Self::Expired => "the permit or browser identity authorization expired",
            Self::TimedOut => "the browser peer operation timed out",
            Self::BrowserUnavailable => "browser WebRTC is unavailable",
            Self::BrowserOperation => "browser WebRTC operation failed",
            Self::SignalRejected => "signed signaling was rejected",
            Self::ManagementFailure(_) => "the management operation was rejected",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PeerError {}

impl PeerError {
    pub fn diagnostic_failure_for_setup(
        &self,
        setup: bool,
    ) -> nestlink_protocol::diagnostics::ConnectionFailure {
        if setup && *self == Self::Expired {
            nestlink_protocol::diagnostics::ConnectionFailure::StartupAuthorizationExpired
        } else {
            self.diagnostic_failure()
        }
    }

    pub fn diagnostic_failure(&self) -> nestlink_protocol::diagnostics::ConnectionFailure {
        use nestlink_protocol::diagnostics::ConnectionFailure as F;
        match self {
            Self::ManagementFailure(failure) => *failure,
            Self::InvalidIceConfiguration | Self::InvalidPathMode => F::InvalidConfiguration,
            Self::InvalidPermit => F::InvalidAuthorization,
            Self::EndpointMismatch => F::EndpointMismatch,
            Self::EndpointLeaseExpired | Self::Expired => F::AuthorizationExpired,
            Self::UnauthorizedTrack => F::TrackNotAuthorized,
            Self::CodecUnavailable => F::CodecUnavailable,
            Self::PathNotPermitted => F::PathNotPermitted,
            Self::RelayUnavailable => F::RelayUnavailable,
            Self::NoSelectedPath => F::NoSelectedPair,
            Self::SelectedPathRejected => F::SelectedPairRejected,
            Self::OfferRequired | Self::UnsupportedTrickleSignal | Self::SignalRejected => {
                F::SignalingRejected
            }
            Self::AnswerRequired => F::AnswerNotConsumed,
            Self::Cancelled => F::Cancelled,
            Self::TimedOut => F::OperationTimeout,
            Self::BrowserUnavailable => F::BrowserUnavailable,
            Self::BrowserOperation => F::BrowserOperation,
        }
    }
}

/// A server entry supplied by deployment configuration, never from a peer signal.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustedIceServer {
    urls: Vec<String>,
    username: Option<String>,
    credential: Option<String>,
}

impl std::fmt::Debug for TrustedIceServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedIceServer")
            .field("urls", &self.urls)
            .field("username", &self.username)
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl Drop for TrustedIceServer {
    fn drop(&mut self) {
        if let Some(credential) = &mut self.credential {
            credential.zeroize();
        }
    }
}

impl TrustedIceServer {
    pub fn stun(url: impl Into<String>) -> Self {
        Self {
            urls: vec![url.into()],
            username: None,
            credential: None,
        }
    }

    pub fn turn(
        urls: Vec<String>,
        username: impl Into<String>,
        credential: impl Into<String>,
    ) -> Self {
        Self {
            urls,
            username: Some(username.into()),
            credential: Some(credential.into()),
        }
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn has_turn(&self) -> bool {
        self.urls
            .iter()
            .any(|url| url.starts_with("turn:") || url.starts_with("turns:"))
    }
}

/// ICE configuration from the deployment's trusted configuration channel.
/// Do not build this from SDP, candidates, query parameters or user-editable data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedIceConfiguration {
    servers: Vec<TrustedIceServer>,
}

impl TrustedIceConfiguration {
    pub fn from_trusted_deployment_config(
        servers: Vec<TrustedIceServer>,
    ) -> Result<Self, PeerError> {
        if servers.len() > MAX_ICE_SERVERS {
            return Err(PeerError::InvalidIceConfiguration);
        }
        let mut seen: Vec<&str> = Vec::new();
        for server in &servers {
            if server.urls.is_empty() || server.urls.len() > MAX_ICE_URLS_PER_SERVER {
                return Err(PeerError::InvalidIceConfiguration);
            }
            let mut contains_turn = false;
            for url in &server.urls {
                let is_turn = validate_ice_url(url)?;
                contains_turn |= is_turn;
                if seen.contains(&url.as_str()) {
                    return Err(PeerError::InvalidIceConfiguration);
                }
                seen.push(url.as_str());
            }
            if contains_turn {
                let Some(username) = server.username.as_deref() else {
                    return Err(PeerError::InvalidIceConfiguration);
                };
                let Some(credential) = server.credential.as_deref() else {
                    return Err(PeerError::InvalidIceConfiguration);
                };
                if username.is_empty()
                    || username.len() > MAX_TURN_USERNAME_BYTES
                    || credential.is_empty()
                    || credential.len() > MAX_TURN_CREDENTIAL_BYTES
                    || username.bytes().any(|byte| byte.is_ascii_control())
                    || credential.bytes().any(|byte| byte.is_ascii_control())
                {
                    return Err(PeerError::InvalidIceConfiguration);
                }
            } else if server.username.is_some() || server.credential.is_some() {
                return Err(PeerError::InvalidIceConfiguration);
            }
        }
        Ok(Self { servers })
    }

    #[cfg(any(target_arch = "wasm32", test))]
    fn has_turn(&self) -> bool {
        self.servers.iter().any(TrustedIceServer::has_turn)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_managed_binding(
    binding: &nestlink_protocol::TurnPeerBindingClaims,
    credentials: &nestlink_protocol::TurnCredentialsClaims,
    host_network_generation: u64,
    controller_candidates: &[String],
    host_candidates: &[String],
    now_ms: u64,
) -> Result<bool, PeerError> {
    binding.validate().map_err(|_| PeerError::SignalRejected)?;
    if binding.deployment_id != credentials.deployment_id
        || binding.security_epoch != credentials.security_epoch
        || binding.session_id != credentials.session_id
        || binding.temporary_identity != credentials.temporary_identity
        || binding.controller_allocation_id != credentials.allocation_id
        || binding.controller_device_id != credentials.device_id
        || binding.controller_network_generation != credentials.network_generation
        || binding.host_network_generation != host_network_generation
        || binding.connection_generation != credentials.connection_generation
        || binding.lease_sequence != credentials.lease_sequence
        || binding.permit_sha256 != credentials.permit_sha256
        || binding.controller_candidates != controller_candidates
        || binding.host_candidates != host_candidates
        || binding.issued_at_unix_ms > now_ms
        || binding.expires_at_unix_ms > credentials.expires_at_unix_ms
    {
        return Err(PeerError::SignalRejected);
    }
    // The SDK has verified the signatures before this check. A response may
    // cross its short binding deadline while fetching the peer key. It grants
    // no relay authority, but is not evidence of a forged signal. Check all
    // context first so expiry cannot hide a candidate/identity mismatch.
    Ok(binding.expires_at_unix_ms > now_ms)
}

fn validate_ice_url(value: &str) -> Result<bool, PeerError> {
    if value.is_empty()
        || value.len() > MAX_ICE_URL_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || value.contains('@')
        || value.contains('#')
    {
        return Err(PeerError::InvalidIceConfiguration);
    }
    let (is_turn, authority) = if let Some(rest) = value.strip_prefix("stun:") {
        (false, rest)
    } else if let Some(rest) = value.strip_prefix("stuns:") {
        (false, rest)
    } else if let Some(rest) = value.strip_prefix("turn:") {
        (true, rest)
    } else if let Some(rest) = value.strip_prefix("turns:") {
        (true, rest)
    } else {
        return Err(PeerError::InvalidIceConfiguration);
    };
    let (host, query) = match authority.split_once('?') {
        Some((host, query)) => (host, Some(query)),
        None => (authority, None),
    };
    if host.is_empty()
        || host.starts_with('/')
        || host.ends_with('/')
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || host.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']'))
        })
    {
        return Err(PeerError::InvalidIceConfiguration);
    }
    if let Some(query) = query
        && (!is_turn || !matches!(query, "transport=udp" | "transport=tcp"))
    {
        return Err(PeerError::InvalidIceConfiguration);
    }
    Ok(is_turn)
}

#[cfg(target_arch = "wasm32")]
fn validate_inputs(
    permit: &VerifiedPermit,
    identity: &DeviceIdentity,
    lease: Option<&BrowserEndpointLease>,
    requested_mode: PeerPathMode,
    ice: &TrustedIceConfiguration,
    now_ms: u64,
) -> Result<PeerPathMode, PeerError> {
    let claims = permit.claims();
    claims.validate().map_err(|_| PeerError::InvalidPermit)?;
    if claims.expires_at_unix_ms <= now_ms {
        return Err(PeerError::InvalidPermit);
    }
    if lease.is_some_and(|lease| {
        lease.device_id != identity.device_id || lease.expires_at_unix_ms <= now_ms
    }) {
        return Err(PeerError::EndpointLeaseExpired);
    }
    let fingerprint = identity.identity.fingerprint();
    if identity.device_id != claims.controller_device_id
        || fingerprint.as_slice() != claims.controller_key_sha256.as_slice()
    {
        return Err(PeerError::EndpointMismatch);
    }
    let mode = effective_path_mode(requested_mode, &claims.paths)?;
    if mode == PeerPathMode::RelayOnly && !ice.has_turn() {
        return Err(PeerError::RelayUnavailable);
    }
    Ok(mode)
}

#[cfg(any(target_arch = "wasm32", test))]
fn effective_path_mode(
    requested: PeerPathMode,
    allowed_paths: &[i32],
) -> Result<PeerPathMode, PeerError> {
    let allows_direct = allowed_paths.contains(&(Path::Direct as i32));
    let allows_relay = allowed_paths.contains(&(Path::Relay as i32));
    match requested {
        PeerPathMode::DirectOnly if allows_direct => Ok(PeerPathMode::DirectOnly),
        PeerPathMode::DirectOnly => Err(PeerError::PathNotPermitted),
        PeerPathMode::RelayOnly if allows_relay => Ok(PeerPathMode::RelayOnly),
        PeerPathMode::RelayOnly => Err(PeerError::PathNotPermitted),
        PeerPathMode::DirectPreferred if allows_direct => Ok(PeerPathMode::DirectPreferred),
        PeerPathMode::DirectPreferred if allows_relay => Ok(PeerPathMode::RelayOnly),
        PeerPathMode::DirectPreferred => Err(PeerError::PathNotPermitted),
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn path_from_candidate_types(local_relay: bool, remote_relay: bool) -> SelectedPath {
    if local_relay || remote_relay {
        SelectedPath::Relay
    } else {
        SelectedPath::Direct
    }
}

#[cfg(test)]
fn authorization_expiry(lease_expires_at_unix_ms: u64, permit_expires_at_unix_ms: u64) -> u64 {
    lease_expires_at_unix_ms.min(permit_expires_at_unix_ms)
}

#[cfg(any(target_arch = "wasm32", test))]
fn next_network_generation(current: u64) -> Result<u64, PeerError> {
    current
        .checked_add(1)
        .filter(|next| *next <= i64::MAX as u64)
        .ok_or(PeerError::SignalRejected)
}

#[cfg(any(target_arch = "wasm32", test))]
fn answer_matches_current_offer(
    current_offer_sequence: u64,
    answer_offer_sequence: u64,
) -> Result<bool, PeerError> {
    if answer_offer_sequence < current_offer_sequence {
        Ok(false)
    } else if answer_offer_sequence == current_offer_sequence {
        Ok(true)
    } else {
        Err(PeerError::SignalRejected)
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn verify_selected_paths(
    mode: PeerPathMode,
    allowed_paths: &[i32],
    selected: &[SelectedPath],
) -> Result<SelectedPath, PeerError> {
    if selected.is_empty() {
        return Err(PeerError::NoSelectedPath);
    }
    let has_direct = allowed_paths.contains(&(Path::Direct as i32));
    let has_relay = allowed_paths.contains(&(Path::Relay as i32));
    let mut saw_direct = false;
    let mut saw_relay = false;
    for path in selected {
        match path {
            SelectedPath::Direct if mode == PeerPathMode::RelayOnly || !has_direct => {
                return Err(PeerError::SelectedPathRejected);
            }
            SelectedPath::Relay if mode == PeerPathMode::DirectOnly || !has_relay => {
                return Err(PeerError::SelectedPathRejected);
            }
            SelectedPath::Mixed
                if mode != PeerPathMode::DirectPreferred || !has_direct || !has_relay =>
            {
                return Err(PeerError::SelectedPathRejected);
            }
            _ => {}
        }
        saw_direct |= matches!(path, SelectedPath::Direct | SelectedPath::Mixed);
        saw_relay |= matches!(path, SelectedPath::Relay | SelectedPath::Mixed);
    }
    match (saw_direct, saw_relay) {
        (true, true) => Ok(SelectedPath::Mixed),
        (true, false) => Ok(SelectedPath::Direct),
        (false, true) => Ok(SelectedPath::Relay),
        (false, false) => Err(PeerError::NoSelectedPath),
    }
}

#[cfg(any(target_arch = "wasm32", test))]
struct PeerPathAuthority {
    mode: PeerPathMode,
    selected: Option<SelectedPath>,
    turn_bound: bool,
}

#[cfg(any(target_arch = "wasm32", test))]
impl PeerPathAuthority {
    fn new(mode: PeerPathMode) -> Self {
        Self {
            mode,
            selected: None,
            turn_bound: false,
        }
    }

    fn requires_turn(&self) -> bool {
        self.mode == PeerPathMode::RelayOnly || self.selected == Some(SelectedPath::Relay)
    }

    fn ready(&self) -> bool {
        match self.selected {
            Some(SelectedPath::Direct) => self.mode != PeerPathMode::RelayOnly,
            Some(SelectedPath::Relay) => self.turn_bound,
            _ => false,
        }
    }

    fn select(
        &mut self,
        paths: &[i32],
        selected: SelectedPath,
        proved_path: Option<Path>,
    ) -> Result<(), PeerError> {
        verify_selected_paths(self.mode, paths, &[selected])?;
        let path = match selected {
            SelectedPath::Direct => Path::Direct,
            SelectedPath::Relay => Path::Relay,
            SelectedPath::Mixed => return Err(PeerError::SelectedPathRejected),
        };
        if proved_path.is_some_and(|proved| proved != path) {
            return Err(PeerError::SelectedPathRejected);
        }
        if selected == SelectedPath::Relay && !self.turn_bound {
            return Err(PeerError::NoSelectedPath);
        }
        self.selected = Some(selected);
        Ok(())
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn turn_sdk_error(error: nestlink_sdk::SdkError) -> PeerError {
    use nestlink_protocol::ErrorCode;
    use nestlink_sdk::SdkError;
    match error {
        SdkError::Timeout | SdkError::BrowserTransport => PeerError::RelayUnavailable,
        SdkError::Transport(error) if error.is_timeout() => PeerError::RelayUnavailable,
        SdkError::Api(status, code)
            if (status.is_server_error()
                && matches!(
                    code,
                    ErrorCode::RelayUnavailable | ErrorCode::TurnUnreachable
                ))
                || (status.as_u16() == 403 && code == ErrorCode::RelayDisabled)
                || (status.as_u16() == 429 && code == ErrorCode::CapacityExceeded) =>
        {
            PeerError::RelayUnavailable
        }
        error => PeerError::ManagementFailure(error.diagnostic_failure()),
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn managed_candidate_addresses(mode: PeerPathMode, sdp: &str) -> Result<Vec<String>, PeerError> {
    let addresses = nestlink_protocol::turn::optional_ice_candidate_addresses(sdp)
        .map_err(|_| PeerError::SignalRejected)?;
    match addresses {
        Some(addresses) => Ok(addresses),
        None if mode == PeerPathMode::RelayOnly => Err(PeerError::RelayUnavailable),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_expiry_does_not_reclassify_endpoint_expiry_or_running_authority() {
        use nestlink_protocol::diagnostics::ConnectionFailure as F;
        assert_eq!(
            PeerError::Expired.diagnostic_failure_for_setup(true),
            F::StartupAuthorizationExpired
        );
        assert_eq!(
            PeerError::Expired.diagnostic_failure_for_setup(false),
            F::AuthorizationExpired
        );
        assert_eq!(
            PeerError::EndpointLeaseExpired.diagnostic_failure_for_setup(true),
            F::AuthorizationExpired
        );
        assert_eq!(
            PeerError::SignalRejected.diagnostic_failure_for_setup(true),
            F::SignalingRejected
        );
    }

    #[test]
    fn throughput_classification_changes_do_not_request_ice_restarts() {
        assert!(network_event_requires_ice_restart("online"));
        assert!(network_event_requires_ice_restart("offline"));
        assert!(!network_event_requires_ice_restart("change"));
        assert!(!network_event_requires_ice_restart("load"));
    }

    #[test]
    fn trusted_ice_configuration_rejects_urls_with_embedded_credentials() {
        assert!(
            TrustedIceConfiguration::from_trusted_deployment_config(vec![TrustedIceServer::stun(
                "stun:stun.example.test:3478"
            ),])
            .is_ok()
        );
        assert!(
            TrustedIceConfiguration::from_trusted_deployment_config(vec![TrustedIceServer::turn(
                vec!["turns:turn.example.test:5349?transport=tcp".into()],
                "short-lived-user",
                "short-lived-credential",
            ),])
            .is_ok()
        );
        assert_eq!(
            TrustedIceConfiguration::from_trusted_deployment_config(vec![TrustedIceServer::stun(
                "stun:user:secret@example.test:3478"
            ),]),
            Err(PeerError::InvalidIceConfiguration)
        );
        assert_eq!(
            TrustedIceConfiguration::from_trusted_deployment_config(vec![TrustedIceServer::turn(
                vec!["turn:turn.example.test:3478".into()],
                "user",
                ""
            ),]),
            Err(PeerError::InvalidIceConfiguration)
        );
    }

    #[test]
    fn relay_only_requires_trusted_turn_and_never_accepts_a_direct_pair() -> Result<(), PeerError> {
        let turn =
            TrustedIceConfiguration::from_trusted_deployment_config(vec![TrustedIceServer::turn(
                vec!["turn:turn.example.test:3478?transport=udp".into()],
                "lease-user",
                "lease-credential",
            )])?;
        assert!(turn.has_turn());
        assert_eq!(
            verify_selected_paths(
                PeerPathMode::RelayOnly,
                &[Path::Direct as i32, Path::Relay as i32],
                &[SelectedPath::Direct],
            ),
            Err(PeerError::SelectedPathRejected)
        );
        assert_eq!(
            verify_selected_paths(
                PeerPathMode::RelayOnly,
                &[Path::Direct as i32, Path::Relay as i32],
                &[SelectedPath::Relay],
            ),
            Ok(SelectedPath::Relay)
        );
        assert_eq!(
            validate_selected_for_mode_without_turn(),
            Err(PeerError::RelayUnavailable)
        );
        Ok(())
    }

    fn validate_selected_for_mode_without_turn() -> Result<(), PeerError> {
        let empty = TrustedIceConfiguration::default();
        if !empty.has_turn() {
            Err(PeerError::RelayUnavailable)
        } else {
            Ok(())
        }
    }

    #[test]
    fn direct_only_rejects_relay_pairs_and_direct_preferred_checks_permit_paths() {
        assert_eq!(
            verify_selected_paths(
                PeerPathMode::DirectOnly,
                &[Path::Direct as i32, Path::Relay as i32],
                &[SelectedPath::Relay],
            ),
            Err(PeerError::SelectedPathRejected)
        );
        assert_eq!(
            verify_selected_paths(
                PeerPathMode::DirectOnly,
                &[Path::Direct as i32],
                &[SelectedPath::Direct],
            ),
            Ok(SelectedPath::Direct)
        );
        assert_eq!(
            verify_selected_paths(
                PeerPathMode::DirectPreferred,
                &[Path::Direct as i32],
                &[SelectedPath::Relay],
            ),
            Err(PeerError::SelectedPathRejected)
        );
        assert_eq!(
            verify_selected_paths(
                PeerPathMode::DirectPreferred,
                &[Path::Direct as i32, Path::Relay as i32],
                &[SelectedPath::Direct, SelectedPath::Relay],
            ),
            Ok(SelectedPath::Mixed)
        );
        for mode in [PeerPathMode::DirectOnly, PeerPathMode::RelayOnly] {
            assert_eq!(
                verify_selected_paths(
                    mode,
                    &[Path::Direct as i32, Path::Relay as i32],
                    &[SelectedPath::Mixed],
                ),
                Err(PeerError::SelectedPathRejected)
            );
        }
    }

    #[test]
    fn direct_preferred_falls_back_to_relay_only_when_the_permit_forbids_direct() {
        assert_eq!(
            effective_path_mode(PeerPathMode::DirectPreferred, &[Path::Relay as i32]),
            Ok(PeerPathMode::RelayOnly)
        );
        assert_eq!(
            effective_path_mode(
                PeerPathMode::DirectPreferred,
                &[Path::Direct as i32, Path::Relay as i32],
            ),
            Ok(PeerPathMode::DirectPreferred)
        );
        assert_eq!(
            effective_path_mode(PeerPathMode::DirectPreferred, &[]),
            Err(PeerError::PathNotPermitted)
        );
    }

    #[test]
    fn direct_path_authority_is_independent_of_optional_turn_lifetime() -> Result<(), PeerError> {
        let paths = [Path::Direct as i32, Path::Relay as i32];
        let mut authority = PeerPathAuthority::new(PeerPathMode::DirectPreferred);
        assert!(!authority.ready());
        assert!(!authority.requires_turn());
        authority.select(&paths, SelectedPath::Direct, None)?;
        assert!(authority.ready());
        assert!(!authority.requires_turn());
        authority.turn_bound = true;
        authority.turn_bound = false; // Optional TURN expires or is revoked.
        assert!(authority.ready());
        assert_eq!(
            authority.select(&paths, SelectedPath::Relay, Some(Path::Direct)),
            Err(PeerError::SelectedPathRejected)
        );
        Ok(())
    }

    #[test]
    fn relay_authority_requires_binding_and_cannot_downgrade_a_proved_path() -> Result<(), PeerError>
    {
        let paths = [Path::Direct as i32, Path::Relay as i32];
        for mode in [PeerPathMode::DirectPreferred, PeerPathMode::RelayOnly] {
            let mut authority = PeerPathAuthority::new(mode);
            assert_eq!(
                authority.select(&paths, SelectedPath::Relay, None),
                Err(PeerError::NoSelectedPath)
            );
            assert!(!authority.ready());
            authority.turn_bound = true;
            authority.select(&paths, SelectedPath::Relay, None)?;
            assert!(authority.requires_turn());
            assert!(authority.ready());
            assert_eq!(
                authority.select(&paths, SelectedPath::Direct, Some(Path::Relay)),
                Err(PeerError::SelectedPathRejected)
            );
            authority.turn_bound = false;
            assert!(!authority.ready());
            assert!(authority.requires_turn());
        }
        Ok(())
    }

    #[test]
    fn optional_turn_failure_preserves_authentication_and_signature_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        use nestlink_protocol::ErrorCode;
        use nestlink_sdk::SdkError;
        for error in [SdkError::Timeout, SdkError::BrowserTransport] {
            assert_eq!(turn_sdk_error(error), PeerError::RelayUnavailable);
        }
        for error in [SdkError::Trust, SdkError::Invalid, SdkError::SignIn] {
            let failure = error.diagnostic_failure();
            assert_eq!(turn_sdk_error(error), PeerError::ManagementFailure(failure));
        }
        for (status, code) in [
            (503u16, ErrorCode::RelayUnavailable),
            (503, ErrorCode::TurnUnreachable),
            (403, ErrorCode::RelayDisabled),
            (429, ErrorCode::CapacityExceeded),
        ] {
            assert_eq!(
                turn_sdk_error(SdkError::Api(status.try_into()?, code)),
                PeerError::RelayUnavailable
            );
        }
        for (status, code) in [
            (403u16, ErrorCode::PermissionRequired),
            (409, ErrorCode::ReplayRejected),
            (401, ErrorCode::RelayUnavailable),
        ] {
            let error = SdkError::Api(status.try_into()?, code);
            let failure = error.diagnostic_failure();
            assert_eq!(turn_sdk_error(error), PeerError::ManagementFailure(failure));
        }
        Ok(())
    }

    #[test]
    fn lan_only_candidates_are_optional_only_when_direct_is_permitted() {
        let sdp = concat!(
            "a=candidate:1 1 UDP 100 192.168.1.10 5000 typ host\r\n",
            "a=candidate:2 1 UDP 90 temporary.local 5001 typ host\r\n",
        );
        assert_eq!(
            managed_candidate_addresses(PeerPathMode::DirectPreferred, sdp),
            Ok(Vec::new())
        );
        assert_eq!(
            managed_candidate_addresses(PeerPathMode::RelayOnly, sdp),
            Err(PeerError::RelayUnavailable)
        );
        let invalid = "a=candidate:1 1 UDP 100 192.168.1.10 5000 typ relay\r\n";
        assert_eq!(
            managed_candidate_addresses(PeerPathMode::DirectPreferred, invalid),
            Err(PeerError::SignalRejected)
        );
        assert_eq!(
            managed_candidate_addresses(PeerPathMode::RelayOnly, invalid),
            Err(PeerError::SignalRejected)
        );
    }

    #[test]
    fn authorization_ends_at_the_earlier_independent_expiry() {
        assert_eq!(authorization_expiry(1_000_000, 15_000), 15_000);
        assert_eq!(authorization_expiry(15_000, 1_000_000), 15_000);
    }

    #[test]
    fn a_candidate_pair_is_relay_if_either_endpoint_uses_turn() {
        assert_eq!(
            path_from_candidate_types(false, false),
            SelectedPath::Direct
        );
        assert_eq!(path_from_candidate_types(true, false), SelectedPath::Relay);
        assert_eq!(path_from_candidate_types(false, true), SelectedPath::Relay);
    }

    #[test]
    fn network_generation_is_monotonic_and_stays_inside_the_protocol_range() {
        assert_eq!(next_network_generation(1), Ok(2));
        assert_eq!(
            next_network_generation(i64::MAX as u64),
            Err(PeerError::SignalRejected)
        );
        assert_eq!(
            next_network_generation(u64::MAX),
            Err(PeerError::SignalRejected)
        );
    }

    #[test]
    fn managed_turn_requires_the_exact_current_offer_and_answer_candidates() {
        use nestlink_protocol::{
            SCHEMA_VERSION, TurnCredentialsClaims, TurnPeerBindingClaims, TurnPurpose,
        };
        let id = |n| format!("{n:08x}-1111-4111-8111-111111111111");
        let binding = TurnPeerBindingClaims {
            schema_version: SCHEMA_VERSION,
            deployment_id: id(1),
            security_epoch: 1,
            session_id: id(2),
            temporary_identity: id(3),
            purpose: TurnPurpose::BrowserWebRtc as i32,
            controller_allocation_id: id(4),
            host_allocation_id: id(5),
            controller_device_id: id(3),
            host_device_id: id(6),
            controller_key_sha256: vec![1; 32],
            host_key_sha256: vec![2; 32],
            controller_network_generation: 2,
            host_network_generation: 4,
            connection_generation: 1,
            lease_sequence: 3,
            permit_sha256: vec![3; 32],
            controller_candidates: vec!["8.8.8.8:42000".into()],
            host_candidates: vec!["1.1.1.1:42001".into()],
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: 5_000,
        };
        let credentials = TurnCredentialsClaims {
            deployment_id: id(1),
            security_epoch: 1,
            session_id: id(2),
            temporary_identity: id(3),
            allocation_id: id(4),
            device_id: id(3),
            network_generation: 2,
            connection_generation: 1,
            lease_sequence: 3,
            permit_sha256: vec![3; 32],
            expires_at_unix_ms: 6_000,
            ..Default::default()
        };
        let check = |b: &TurnPeerBindingClaims, host_generation, now| {
            validate_managed_binding(
                b,
                &credentials,
                host_generation,
                &binding.controller_candidates,
                &binding.host_candidates,
                now,
            )
        };
        assert_eq!(check(&binding, 4, 2_000), Ok(true));
        assert!(check(&binding, 3, 2_000).is_err());
        assert!(check(&binding, 4, 999).is_err());
        assert_eq!(check(&binding, 4, 5_000), Ok(false));
        assert_eq!(check(&binding, 4, 6_000), Ok(false));
        let mut changed = binding.clone();
        changed.controller_candidates.push("9.9.9.9:42002".into());
        assert!(check(&changed, 4, 2_000).is_err());
        let mut changed = binding.clone();
        changed.controller_allocation_id = id(7);
        assert!(check(&changed, 4, 2_000).is_err());
        let mut changed = binding.clone();
        changed.lease_sequence += 1;
        assert!(check(&changed, 4, 2_000).is_err());
        let mut changed = binding.clone();
        changed.controller_network_generation += 1;
        assert!(check(&changed, 4, 2_000).is_err());
        let mut changed = binding.clone();
        changed.host_candidates = binding.controller_candidates.clone();
        assert!(check(&changed, 4, 2_000).is_err());
        let mut changed = binding.clone();
        changed.expires_at_unix_ms = 6_001;
        assert!(check(&changed, 4, 2_000).is_err());
        let mut changed = binding.clone();
        changed.permit_sha256[0] ^= 1;
        assert!(check(&changed, 4, 2_000).is_err());
        assert!(check(&changed, 4, 6_000).is_err());
    }

    #[test]
    fn ice_diagnostics_do_not_expose_turn_passwords() -> Result<(), PeerError> {
        let ice =
            TrustedIceConfiguration::from_trusted_deployment_config(vec![TrustedIceServer::turn(
                vec!["turns:turn.example.test:443?transport=tcp".into()],
                "user",
                "private-password",
            )])?;
        let diagnostic = format!("{ice:?}");
        assert!(!diagnostic.contains("private-password"));
        assert!(diagnostic.contains("[redacted]"));
        Ok(())
    }

    #[test]
    fn only_the_latest_offer_answer_is_applied() {
        assert_eq!(answer_matches_current_offer(4, 3), Ok(false));
        assert_eq!(answer_matches_current_offer(4, 4), Ok(true));
        assert_eq!(
            answer_matches_current_offer(4, 5),
            Err(PeerError::SignalRejected)
        );
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use crate::browser_data::{BrowserDataChannels, BrowserDataError};
    use crate::browser_diagnostics::BrowserConnectionDiagnostics;
    use crate::browser_displays::{DisplayClientState, DisplayPermitWindow, PendingDisplayCatalog};
    use crate::browser_input::BrowserInputEvent;
    use crate::browser_sdp::rtc_session_description_init;
    use futures_util::{future::select, lock::Mutex};
    use gloo_timers::future::TimeoutFuture;
    use js_sys::{Array, ArrayBuffer, Date, Iterator, Uint8Array};
    use nestlink_identity::verify_endpoint_proof;
    use nestlink_policy::PathSet;
    use nestlink_protocol::diagnostics::{ConnectionFailure, ConnectionStage, ConnectionTimeline};
    use nestlink_protocol::native_displays::DisplayEnvelope;
    use nestlink_protocol::turn::TURN_BINDING_BYTES;
    use nestlink_protocol::{
        NativeProof, Permission, PermitClaims,
        api::{Candidate, SignalPayload, WebRtcDescription},
        webrtc::{
            MAX_WEBRTC_CONTROL_BYTES, WEBRTC_CONTROL_LABEL, WebRtcControl, WebRtcDisplayControl,
            WebRtcInputAction, restrict_media_sdp, validate_media_sdp,
        },
    };
    use nestlink_sdk::{Sdk, SignalCursor, TurnCredentials};
    use nestlink_session::{ClockSample, EndpointRole, Session, SessionBinding};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::future::Future;
    use wasm_bindgen::{JsCast, JsValue, closure::Closure};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{
        Document, Event, MessageEvent, RtcConfiguration, RtcDataChannel, RtcDataChannelInit,
        RtcDataChannelType, RtcIceCandidateInit, RtcIceCandidatePairStats, RtcIceCandidateStats,
        RtcIceGatheringState, RtcIceServer, RtcIceTransportPolicy, RtcOfferOptions,
        RtcPeerConnection, RtcPeerConnectionState, RtcRtpReceiver, RtcRtpTransceiverDirection,
        RtcRtpTransceiverInit, RtcSdpType, RtcSessionDescriptionInit, RtcStats,
        RtcStatsIceCandidatePairState, RtcStatsIceCandidateType, RtcStatsReport, RtcStatsType,
        RtcTrackEvent,
    };

    #[derive(Clone)]
    pub struct PeerCancellation {
        cancelled: Rc<Cell<bool>>,
        peer: RtcPeerConnection,
        expiry_timer: i32,
        data: BrowserDataChannels,
        diagnostics: BrowserConnectionDiagnostics,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PeerInputLayout {
        pub left: i32,
        pub top: i32,
        pub width: u32,
        pub height: u32,
        pub input_epoch: u64,
        pub layout_epoch: u64,
    }

    #[derive(Default)]
    struct InputSendState {
        scroll_supported: bool,
        layout: Option<PeerInputLayout>,
        pending_layout: Option<PeerInputLayout>,
        suspended: bool,
        sequence: u64,
    }

    struct ControlReceiveState {
        pending: Rc<RefCell<Option<WebRtcControl>>>,
        proofs: Rc<RefCell<VecDeque<WebRtcControl>>>,
        proof_complete: Rc<Cell<bool>>,
        acceptance_expected: Rc<Cell<bool>>,
        accepted_queued: Rc<Cell<bool>>,
        pending_catalog: Rc<RefCell<PendingDisplayCatalog>>,
        input: Rc<RefCell<InputSendState>>,
        displays: Rc<RefCell<DisplayClientState>>,
        display_deadline: Rc<Cell<Option<f64>>>,
        display_permit: Rc<RefCell<Option<VerifiedPermit>>>,
    }

    #[derive(Clone)]
    pub struct PeerInputSender {
        peer: RtcPeerConnection,
        channel: RtcDataChannel,
        cancelled: Rc<Cell<bool>>,
        authority: Rc<RefCell<PeerAuthority>>,
        proof_complete: Rc<Cell<bool>>,
        state: Rc<RefCell<InputSendState>>,
    }

    impl PeerInputSender {
        pub fn send(&self, event: BrowserInputEvent) -> Result<(), PeerError> {
            let send = || {
                check_authority(&self.peer, &self.cancelled, &self.authority)?;
                if !self.proof_complete.get() || !self.authority.borrow().path.ready() {
                    return Err(PeerError::EndpointMismatch);
                }
                let authority = self.authority.borrow();
                let claims = authority.permit.claims();
                if !claims.permissions.contains(&(Permission::Input as i32)) {
                    return Err(PeerError::InvalidPermit);
                }
                let mut state = self.state.borrow_mut();
                // An old capture can still dispatch a queued DOM event while a
                // display transaction is pending. It must not cross the epoch.
                if state.suspended {
                    return Ok(());
                }
                let layout = state.layout.ok_or(PeerError::SignalRejected)?;
                let message = match event {
                    BrowserInputEvent::Key { usage, down } => {
                        let sequence = next_input_sequence(state.sequence)?;
                        WebRtcControl::InputEvent {
                            schema_version: claims.schema_version,
                            session_id: claims.session_id.clone(),
                            connection_generation: claims.connection_generation,
                            lease_sequence: claims.lease_sequence,
                            input_epoch: layout.input_epoch,
                            layout_epoch: layout.layout_epoch,
                            sequence,
                            action: WebRtcInputAction::Key { usage, down },
                        }
                    }
                    BrowserInputEvent::Pointer { button, down, x, y } => {
                        let sequence = next_input_sequence(state.sequence)?;
                        WebRtcControl::InputEvent {
                            schema_version: claims.schema_version,
                            session_id: claims.session_id.clone(),
                            connection_generation: claims.connection_generation,
                            lease_sequence: claims.lease_sequence,
                            input_epoch: layout.input_epoch,
                            layout_epoch: layout.layout_epoch,
                            sequence,
                            action: WebRtcInputAction::Pointer { button, down, x, y },
                        }
                    }
                    BrowserInputEvent::Scroll { x, y } => {
                        if !state.scroll_supported {
                            return Ok(());
                        }
                        let sequence = next_input_sequence(state.sequence)?;
                        WebRtcControl::InputEvent {
                            schema_version: claims.schema_version,
                            session_id: claims.session_id.clone(),
                            connection_generation: claims.connection_generation,
                            lease_sequence: claims.lease_sequence,
                            input_epoch: layout.input_epoch,
                            layout_epoch: layout.layout_epoch,
                            sequence,
                            action: WebRtcInputAction::Scroll { x, y },
                        }
                    }
                    BrowserInputEvent::Text(text) => {
                        let sequence = next_input_sequence(state.sequence)?;
                        WebRtcControl::InputEvent {
                            schema_version: claims.schema_version,
                            session_id: claims.session_id.clone(),
                            connection_generation: claims.connection_generation,
                            lease_sequence: claims.lease_sequence,
                            input_epoch: layout.input_epoch,
                            layout_epoch: layout.layout_epoch,
                            sequence,
                            action: WebRtcInputAction::Text { text },
                        }
                    }
                    BrowserInputEvent::ReleaseAll => WebRtcControl::InputReleaseAll {
                        schema_version: claims.schema_version,
                        session_id: claims.session_id.clone(),
                        connection_generation: claims.connection_generation,
                        lease_sequence: claims.lease_sequence,
                        input_epoch: layout.input_epoch,
                        layout_epoch: layout.layout_epoch,
                    },
                };
                let advances_sequence = matches!(&message, WebRtcControl::InputEvent { .. });
                let bytes = message
                    .encode_validated(claims)
                    .map_err(|_| PeerError::SignalRejected)?;
                if self.channel.ready_state() != web_sys::RtcDataChannelState::Open
                    || self.channel.buffered_amount() > 1_048_576
                {
                    return Err(PeerError::BrowserOperation);
                }
                self.channel
                    .send_with_u8_array(&bytes)
                    .map_err(|_| PeerError::BrowserOperation)?;
                if advances_sequence {
                    state.sequence = next_input_sequence(state.sequence)?;
                }
                Ok(())
            };
            let result = send();
            if result.is_err() {
                close_peer(&self.peer, &self.cancelled);
            }
            result
        }
    }

    fn next_input_sequence(sequence: u64) -> Result<u64, PeerError> {
        sequence
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or(PeerError::SignalRejected)
    }

    impl PeerCancellation {
        pub fn connection_timeline(&self) -> ConnectionTimeline {
            self.diagnostics.snapshot()
        }
        pub fn observe_video_progress(&self) {
            self.diagnostics
                .mark_once(ConnectionStage::FirstVideoProgressObserved);
        }
        pub fn record_unclassified_failure(&self) {
            self.diagnostics.failure(ConnectionFailure::Unclassified);
        }
        pub fn cancel(&self) {
            self.diagnostics.mark_once(ConnectionStage::Stopped);
            self.data.close();
            close_peer(&self.peer, &self.cancelled);
            if let Some(window) = web_sys::window() {
                window.clear_interval_with_handle(self.expiry_timer);
            }
        }

        pub fn is_cancelled(&self) -> bool {
            self.cancelled.get()
        }
    }

    fn close_peer(peer: &RtcPeerConnection, cancelled: &Cell<bool>) {
        cancelled.set(true);
        peer.set_ontrack(None);
        peer.set_oniceconnectionstatechange(None);
        peer.set_onconnectionstatechange(None);
        for receiver in peer.get_receivers().iter() {
            if let Ok(receiver) = receiver.dyn_into::<RtcRtpReceiver>() {
                receiver.track().stop();
            }
        }
        peer.close();
    }

    struct PeerAuthority {
        permit: VerifiedPermit,
        endpoint_deadline_ms: f64,
        permit_deadline_ms: f64,
        last_unix_ms: u64,
        last_monotonic_ms: f64,
        last_request_ms: f64,
        proved_session: Option<Session>,
        turn_deadline_ms: Option<f64>,
        turn_expires_at_unix_ms: Option<u64>,
        turn_binding_deadline_ms: Option<f64>,
        path: PeerPathAuthority,
    }

    impl PeerAuthority {
        fn new(
            permit: VerifiedPermit,
            lease: Option<&BrowserEndpointLease>,
            mode: PeerPathMode,
        ) -> Result<Self, PeerError> {
            let unix_ms = now_ms()?;
            let monotonic_ms = monotonic_ms()?;
            let claims = permit.claims();
            if claims.issued_at_unix_ms > unix_ms
                || claims.expires_at_unix_ms <= unix_ms
                || lease.is_some_and(|lease| lease.expires_at_unix_ms <= unix_ms)
            {
                return Err(PeerError::InvalidPermit);
            }
            let remaining = (claims.expires_at_unix_ms - unix_ms)
                .min(claims.expires_at_unix_ms - claims.issued_at_unix_ms);
            Ok(Self {
                endpoint_deadline_ms: lease.map_or(f64::INFINITY, |lease| {
                    monotonic_ms + (lease.expires_at_unix_ms - unix_ms) as f64
                }),
                permit_deadline_ms: monotonic_ms + remaining as f64,
                last_unix_ms: unix_ms,
                last_monotonic_ms: monotonic_ms,
                last_request_ms: monotonic_ms,
                permit,
                proved_session: None,
                turn_deadline_ms: None,
                turn_expires_at_unix_ms: None,
                turn_binding_deadline_ms: None,
                path: PeerPathAuthority::new(mode),
            })
        }

        fn check(&mut self) -> Result<(), PeerError> {
            let unix_ms = now_ms()?;
            let monotonic_ms = monotonic_ms()?;
            if unix_ms < self.last_unix_ms
                || monotonic_ms < self.last_monotonic_ms
                || monotonic_ms >= self.endpoint_deadline_ms
                || monotonic_ms >= self.permit_deadline_ms
                || unix_ms >= self.permit.claims().expires_at_unix_ms
            {
                return Err(PeerError::Expired);
            }
            self.last_unix_ms = unix_ms;
            self.last_monotonic_ms = monotonic_ms;
            let turn_expired = self
                .turn_deadline_ms
                .is_some_and(|deadline| monotonic_ms >= deadline)
                || self
                    .turn_expires_at_unix_ms
                    .is_some_and(|deadline| unix_ms >= deadline);
            if turn_expired && self.path.requires_turn() {
                return Err(PeerError::Expired);
            }
            if turn_expired
                || self
                    .turn_binding_deadline_ms
                    .is_some_and(|deadline| monotonic_ms >= deadline)
            {
                self.path.turn_bound = false;
            }
            if let Some(session) = &mut self.proved_session {
                session
                    .check_clock(ClockSample {
                        monotonic_ms: monotonic_ms as u64,
                        unix_ms,
                    })
                    .map_err(|_| PeerError::Expired)?;
            }
            Ok(())
        }

        fn authorize_turn(
            &mut self,
            credentials: &TurnCredentials,
            request_started_ms: f64,
        ) -> Result<(), PeerError> {
            self.check()?;
            credentials
                .authorize(&self.permit, self.last_unix_ms)
                .map_err(|_| PeerError::SignalRejected)?;
            if request_started_ms > self.last_monotonic_ms {
                return Err(PeerError::BrowserOperation);
            }
            let c = credentials.claims();
            let remaining = (c.expires_at_unix_ms - self.last_unix_ms)
                .min(c.expires_at_unix_ms - c.issued_at_unix_ms);
            let deadline = request_started_ms + remaining as f64;
            if deadline <= self.last_monotonic_ms {
                return Err(PeerError::Expired);
            }
            self.turn_deadline_ms = Some(deadline);
            self.turn_expires_at_unix_ms = Some(c.expires_at_unix_ms);
            Ok(())
        }

        fn replace(
            &mut self,
            permit: VerifiedPermit,
            request_started_ms: f64,
        ) -> Result<(), PeerError> {
            self.check()?;
            let old = self.permit.claims();
            let new = permit.claims();
            let mut expected = old.clone();
            expected.lease_sequence = new.lease_sequence;
            expected.issued_at_unix_ms = new.issued_at_unix_ms;
            expected.expires_at_unix_ms = new.expires_at_unix_ms;
            if self.permit.issuer() != permit.issuer()
                || &expected != new
                || old.lease_sequence.checked_add(1) != Some(new.lease_sequence)
                || new.issued_at_unix_ms < old.issued_at_unix_ms
                || new.issued_at_unix_ms > self.last_unix_ms
                || new.expires_at_unix_ms <= self.last_unix_ms
                || request_started_ms <= self.last_request_ms
                || request_started_ms > self.last_monotonic_ms
            {
                return Err(PeerError::InvalidPermit);
            }
            let remaining = (new.expires_at_unix_ms - self.last_unix_ms)
                .min(new.expires_at_unix_ms - new.issued_at_unix_ms);
            let deadline = request_started_ms + remaining as f64;
            if deadline <= self.last_monotonic_ms {
                return Err(PeerError::Expired);
            }
            if let Some(session) = &mut self.proved_session {
                session
                    .renew(
                        permit.clone(),
                        request_started_ms as u64,
                        ClockSample {
                            monotonic_ms: self.last_monotonic_ms as u64,
                            unix_ms: self.last_unix_ms,
                        },
                    )
                    .map_err(|_| PeerError::InvalidPermit)?;
            }
            self.permit_deadline_ms = deadline;
            self.last_request_ms = request_started_ms;
            self.permit = permit;
            Ok(())
        }
    }

    fn check_authority(
        peer: &RtcPeerConnection,
        cancelled: &Cell<bool>,
        authority: &RefCell<PeerAuthority>,
    ) -> Result<(), PeerError> {
        if cancelled.get() || peer.connection_state() == RtcPeerConnectionState::Closed {
            return Err(PeerError::Cancelled);
        }
        let result = authority.borrow_mut().check();
        if result.is_err() {
            close_peer(peer, cancelled);
        } else if !authority.borrow().path.ready() {
            for receiver in peer.get_receivers().iter() {
                if let Ok(receiver) = receiver.dyn_into::<RtcRtpReceiver>() {
                    receiver.track().set_enabled(false);
                }
            }
        }
        result
    }

    fn verify_live_path(
        authority: &RefCell<PeerAuthority>,
        selected: SelectedPath,
    ) -> Result<(), PeerError> {
        let mut authority = authority.borrow_mut();
        let proved_path = authority
            .proved_session
            .as_ref()
            .map(|session| {
                Path::try_from(session.proof_transcript().path)
                    .map_err(|_| PeerError::SelectedPathRejected)
            })
            .transpose()?;
        let paths = authority.permit.claims().paths.clone();
        authority.path.select(&paths, selected, proved_path)
    }

    struct PageLifecycleGuard {
        window: web_sys::Window,
        document: Document,
        handler: Closure<dyn FnMut(Event)>,
    }

    impl PageLifecycleGuard {
        fn attach(
            window: web_sys::Window,
            peer: &RtcPeerConnection,
            cancelled: Rc<Cell<bool>>,
        ) -> Result<Self, PeerError> {
            let document = window.document().ok_or(PeerError::BrowserUnavailable)?;
            let lifecycle_peer = peer.clone();
            let handler = Closure::wrap(Box::new(move |_event: Event| {
                close_peer(&lifecycle_peer, &cancelled);
            }) as Box<dyn FnMut(Event)>);
            window
                .add_event_listener_with_callback("pagehide", handler.as_ref().unchecked_ref())
                .map_err(|_| PeerError::BrowserUnavailable)?;
            if document
                .add_event_listener_with_callback("freeze", handler.as_ref().unchecked_ref())
                .is_err()
            {
                let _ = window.remove_event_listener_with_callback(
                    "pagehide",
                    handler.as_ref().unchecked_ref(),
                );
                return Err(PeerError::BrowserUnavailable);
            }
            Ok(Self {
                window,
                document,
                handler,
            })
        }
    }

    impl Drop for PageLifecycleGuard {
        fn drop(&mut self) {
            let callback = self.handler.as_ref().unchecked_ref();
            let _ = self
                .window
                .remove_event_listener_with_callback("pagehide", callback);
            let _ = self
                .document
                .remove_event_listener_with_callback("freeze", callback);
        }
    }

    pub struct BrowserPeer {
        diagnostics: BrowserConnectionDiagnostics,
        peer: RtcPeerConnection,
        sdk: Rc<Mutex<Sdk>>,
        permit: VerifiedPermit,
        identity: DeviceIdentity,
        mode: PeerPathMode,
        cursor: SignalCursor,
        local_sequence: u64,
        local_offer_sequence: u64,
        local_ice_signal: Option<SignalPayload>,
        remote_answer_sequence: u64,
        remote_ice: nestlink_protocol::ice::IceSnapshotCursor,
        network_generation: u64,
        remote_network_generation: u64,
        local_candidate_addresses: Vec<String>,
        remote_candidate_addresses: Vec<String>,
        direct_ice: TrustedIceConfiguration,
        turn_credentials: Option<TurnCredentials>,
        offer_published: bool,
        remote_answer_set: bool,
        cancelled: Rc<Cell<bool>>,
        expiry_timer: i32,
        expiry_handler: Closure<dyn FnMut()>,
        path_monitor: Closure<dyn FnMut()>,
        track_handler: Option<Closure<dyn FnMut(RtcTrackEvent)>>,
        authority: Rc<RefCell<PeerAuthority>>,
        control_channel: RtcDataChannel,
        control_handler: Closure<dyn FnMut(MessageEvent)>,
        pending_renewal: Rc<RefCell<Option<WebRtcControl>>>,
        proof_messages: Rc<RefCell<VecDeque<WebRtcControl>>>,
        proof_complete: Rc<Cell<bool>>,
        acceptance_expected: Rc<Cell<bool>>,
        pending_catalog: Rc<RefCell<PendingDisplayCatalog>>,
        input_state: Rc<RefCell<InputSendState>>,
        display_state: Rc<RefCell<DisplayClientState>>,
        display_deadline: Rc<Cell<Option<f64>>>,
        display_permit: Rc<RefCell<Option<VerifiedPermit>>>,
        data: BrowserDataChannels,
        _page_lifecycle: PageLifecycleGuard,
    }

    impl BrowserPeer {
        /// Creates a receive-only controller peer. `ice` must come from the
        /// deployment's pinned configuration channel; it is never inferred from
        /// SDP or remote candidates. This constructor is retained for short-lived
        /// browser endpoints that carry a server registration lease.
        pub fn new(
            sdk: Rc<Mutex<Sdk>>,
            permit: VerifiedPermit,
            identity: DeviceIdentity,
            lease: BrowserEndpointLease,
            ice: TrustedIceConfiguration,
            mode: PeerPathMode,
        ) -> Result<Self, PeerError> {
            Self::new_with_lease(sdk, permit, identity, Some(lease), ice, mode)
        }

        /// Creates a peer for a registered browser installation. The signed
        /// remote permit, device revocation and host renewal remain the active
        /// authorization; there is no separate temporary-endpoint deadline.
        pub fn new_persistent(
            sdk: Rc<Mutex<Sdk>>,
            permit: VerifiedPermit,
            identity: DeviceIdentity,
            ice: TrustedIceConfiguration,
            mode: PeerPathMode,
        ) -> Result<Self, PeerError> {
            Self::new_with_lease(sdk, permit, identity, None, ice, mode)
        }

        fn new_with_lease(
            sdk: Rc<Mutex<Sdk>>,
            permit: VerifiedPermit,
            identity: DeviceIdentity,
            lease: Option<BrowserEndpointLease>,
            ice: TrustedIceConfiguration,
            mode: PeerPathMode,
        ) -> Result<Self, PeerError> {
            let now = now_ms()?;
            let mode = validate_inputs(&permit, &identity, lease.as_ref(), mode, &ice, now)?;
            let configuration = rtc_configuration(&ice, mode, permit.claims().paths.as_slice())?;
            let window = web_sys::window().ok_or(PeerError::BrowserUnavailable)?;
            let peer = RtcPeerConnection::new_with_configuration(&configuration)
                .map_err(|_| PeerError::BrowserUnavailable)?;
            let transceiver = RtcRtpTransceiverInit::new();
            transceiver.set_direction(RtcRtpTransceiverDirection::Recvonly);
            if permit
                .claims()
                .permissions
                .contains(&(Permission::Audio as i32))
            {
                peer.add_transceiver_with_str_and_init("audio", &transceiver);
            }
            if permit
                .claims()
                .permissions
                .contains(&(Permission::View as i32))
            {
                peer.add_transceiver_with_str_and_init("video", &transceiver);
            }
            let control_options = RtcDataChannelInit::new();
            control_options.set_ordered(true);
            let control_channel = peer
                .create_data_channel_with_data_channel_dict(WEBRTC_CONTROL_LABEL, &control_options);
            control_channel.set_binary_type(RtcDataChannelType::Arraybuffer);

            let cursor =
                SignalCursor::new(&permit, &identity).map_err(|_| PeerError::EndpointMismatch)?;
            let cancelled = Rc::new(Cell::new(false));
            let authority = match PeerAuthority::new(permit.clone(), lease.as_ref(), mode) {
                Ok(authority) => Rc::new(RefCell::new(authority)),
                Err(problem) => {
                    peer.close();
                    return Err(problem);
                }
            };
            let proof_complete = Rc::new(Cell::new(false));
            let data_peer = peer.clone();
            let data_cancelled = cancelled.clone();
            let data_authority = authority.clone();
            let data_proof = proof_complete.clone();
            let authorize_data = Rc::new(
                move |kind: nestlink_protocol::webrtc_data::WebRtcDataChannel| {
                    check_authority(&data_peer, &data_cancelled, &data_authority)
                        .map_err(|_| BrowserDataError::Stopped)?;
                    if !data_proof.get() || !data_authority.borrow().path.ready() {
                        return Err(BrowserDataError::Denied);
                    }
                    let mut state = data_authority.borrow_mut();
                    let at = state.last_monotonic_ms as u64;
                    let session = state
                        .proved_session
                        .as_mut()
                        .ok_or(BrowserDataError::Denied)?;
                    let path = Path::try_from(session.proof_transcript().path)
                        .map_err(|_| BrowserDataError::Protocol)?;
                    session
                        .authorize(kind.permission(), path, at)
                        .map_err(|_| BrowserDataError::Denied)
                },
            );
            let stop_data_peer = peer.clone();
            let stop_data_cancelled = cancelled.clone();
            let data = BrowserDataChannels::new(
                &peer,
                permit.claims(),
                permit.digest(),
                authorize_data,
                Rc::new(move || close_peer(&stop_data_peer, &stop_data_cancelled)),
            )
            .map_err(|_| {
                close_peer(&peer, &cancelled);
                PeerError::InvalidPermit
            })?;
            let expiry_cancelled = cancelled.clone();
            let expiry_peer = peer.clone();
            let expiry_authority = authority.clone();
            let expiry_data = data.clone();
            let expiry_handler = Closure::wrap(Box::new(move || {
                if check_authority(&expiry_peer, &expiry_cancelled, &expiry_authority).is_err()
                    || expiry_data.check_deadlines().is_err()
                {
                    expiry_data.close();
                }
            }) as Box<dyn FnMut()>);
            // Registration and session permits have independent lifetimes. The
            // peer must stop at whichever authorization expires first.
            let expiry_timer = match window.set_interval_with_callback_and_timeout_and_arguments_0(
                expiry_handler.as_ref().unchecked_ref(),
                POLL_INTERVAL_MS as i32,
            ) {
                Ok(timer) => timer,
                Err(_) => {
                    peer.close();
                    return Err(PeerError::BrowserUnavailable);
                }
            };

            let page_lifecycle =
                match PageLifecycleGuard::attach(window.clone(), &peer, cancelled.clone()) {
                    Ok(guard) => guard,
                    Err(problem) => {
                        window.clear_interval_with_handle(expiry_timer);
                        peer.close();
                        return Err(problem);
                    }
                };

            let monitor_peer = peer.clone();
            let monitor_cancelled = cancelled.clone();
            let monitor_mode = mode;
            let monitor_paths = permit.claims().paths.clone();
            let monitor_authority = authority.clone();
            let path_monitor = Closure::wrap(Box::new(move || {
                if check_authority(&monitor_peer, &monitor_cancelled, &monitor_authority).is_err() {
                    return;
                }
                match monitor_peer.connection_state() {
                    RtcPeerConnectionState::Connected => {}
                    RtcPeerConnectionState::Failed | RtcPeerConnectionState::Closed => {
                        close_peer(&monitor_peer, &monitor_cancelled);
                        return;
                    }
                    _ => return,
                }
                let peer = monitor_peer.clone();
                let cancelled = monitor_cancelled.clone();
                let mode = monitor_mode;
                let paths = monitor_paths.clone();
                let authority = monitor_authority.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let verified = match monotonic_ms() {
                        Ok(now) => {
                            wait_for_selected_path(
                                &peer,
                                &cancelled,
                                &authority,
                                mode,
                                &paths,
                                now + 10_000.0,
                            )
                            .await
                        }
                        Err(problem) => Err(problem),
                    };
                    if verified.is_err() || check_authority(&peer, &cancelled, &authority).is_err()
                    {
                        close_peer(&peer, &cancelled);
                    }
                });
            }) as Box<dyn FnMut()>);
            peer.set_oniceconnectionstatechange(Some(path_monitor.as_ref().unchecked_ref()));
            peer.set_onconnectionstatechange(Some(path_monitor.as_ref().unchecked_ref()));

            let pending_renewal = Rc::new(RefCell::new(None));
            let proof_messages = Rc::new(RefCell::new(VecDeque::new()));
            let acceptance_expected = Rc::new(Cell::new(false));
            let accepted_queued = Rc::new(Cell::new(false));
            let pending_catalog = Rc::new(RefCell::new(PendingDisplayCatalog::default()));
            let input_state = Rc::new(RefCell::new(InputSendState {
                suspended: true,
                ..InputSendState::default()
            }));
            let display_state = Rc::new(RefCell::new(DisplayClientState::new(
                permit.claims().session_id.clone(),
                permit.claims().connection_generation,
                permit
                    .claims()
                    .permissions
                    .contains(&(Permission::Input as i32)),
            )));
            let display_deadline = Rc::new(Cell::new(None));
            let display_permit = Rc::new(RefCell::new(None));
            let control_handler = renewal_handler(
                &peer,
                &control_channel,
                cancelled.clone(),
                authority.clone(),
                ControlReceiveState {
                    pending: pending_renewal.clone(),
                    proofs: proof_messages.clone(),
                    proof_complete: proof_complete.clone(),
                    acceptance_expected: acceptance_expected.clone(),
                    accepted_queued,
                    pending_catalog: pending_catalog.clone(),
                    input: input_state.clone(),
                    displays: display_state.clone(),
                    display_deadline: display_deadline.clone(),
                    display_permit: display_permit.clone(),
                },
            );
            control_channel.set_onmessage(Some(control_handler.as_ref().unchecked_ref()));

            let diagnostics = BrowserConnectionDiagnostics::new(
                &permit.claims().session_id,
                permit.claims().connection_generation,
                &identity.device_id,
                &permit.claims().host_device_id,
            );
            diagnostics.mark(ConnectionStage::PeerCreated);
            Ok(Self {
                diagnostics,
                peer,
                sdk,
                permit,
                identity,
                mode,
                cursor,
                local_sequence: 0,
                local_offer_sequence: 0,
                local_ice_signal: None,
                remote_answer_sequence: 0,
                remote_ice: Default::default(),
                network_generation: 1,
                remote_network_generation: 0,
                local_candidate_addresses: Vec::new(),
                remote_candidate_addresses: Vec::new(),
                direct_ice: TrustedIceConfiguration {
                    servers: ice
                        .servers
                        .iter()
                        .filter(|server| !server.has_turn())
                        .cloned()
                        .collect(),
                },
                turn_credentials: None,
                offer_published: false,
                remote_answer_set: false,
                cancelled,
                expiry_timer,
                expiry_handler,
                path_monitor,
                track_handler: None,
                authority,
                control_channel,
                control_handler,
                pending_renewal,
                proof_messages,
                proof_complete,
                acceptance_expected,
                pending_catalog,
                input_state,
                display_state,
                display_deadline,
                display_permit,
                data,
                _page_lifecycle: page_lifecycle,
            })
        }

        /// Obtain signed, short-lived deployment credentials before gathering.
        /// The peer's SDP can never supply TURN servers or passwords.
        pub async fn new_managed(
            sdk: Rc<Mutex<Sdk>>,
            permit: VerifiedPermit,
            identity: DeviceIdentity,
            lease: BrowserEndpointLease,
            mode: PeerPathMode,
        ) -> Result<Self, PeerError> {
            Self::new_managed_with_lease(sdk, permit, identity, Some(lease), mode).await
        }

        /// Uses the same managed TURN and renewal flow for a permanent browser
        /// controller device. Session permits still bound every operation.
        pub async fn new_managed_persistent(
            sdk: Rc<Mutex<Sdk>>,
            permit: VerifiedPermit,
            identity: DeviceIdentity,
            mode: PeerPathMode,
        ) -> Result<Self, PeerError> {
            Self::new_managed_with_lease(sdk, permit, identity, None, mode).await
        }

        async fn new_managed_with_lease(
            sdk: Rc<Mutex<Sdk>>,
            permit: VerifiedPermit,
            identity: DeviceIdentity,
            lease: Option<BrowserEndpointLease>,
            mode: PeerPathMode,
        ) -> Result<Self, PeerError> {
            let mode = effective_path_mode(mode, &permit.claims().paths)?;
            let stun = if mode != PeerPathMode::RelayOnly {
                let config = sdk
                    .lock()
                    .await
                    .native_discovery_config()
                    .await
                    .map_err(|_| PeerError::InvalidIceConfiguration)?;
                let servers = config
                    .webrtc_stun_urls()
                    .map_err(|_| PeerError::InvalidIceConfiguration)?
                    .into_iter()
                    .map(TrustedIceServer::stun)
                    .collect();
                TrustedIceConfiguration::from_trusted_deployment_config(servers)?
            } else {
                TrustedIceConfiguration::default()
            };
            if mode == PeerPathMode::DirectOnly
                || !permit.claims().paths.contains(&(Path::Relay as i32))
            {
                return Self::new_with_lease(sdk, permit, identity, lease, stun, mode);
            }
            let mut initial = PeerAuthority::new(permit.clone(), lease.as_ref(), mode)?;
            let started = monotonic_ms()?;
            let request_budget = if mode == PeerPathMode::DirectPreferred {
                3_000
            } else {
                MAX_OPERATION_MS
            };
            let deadline = (started + f64::from(request_budget))
                .min(initial.permit_deadline_ms)
                .min(initial.endpoint_deadline_ms);
            let allocation_id = uuid::Uuid::new_v4().to_string();
            let credentials = {
                let request = async {
                    sdk.lock()
                        .await
                        .reserve_turn_credentials(&identity, &permit, &allocation_id, 1, now_ms()?)
                        .await
                        .map_err(turn_sdk_error)
                };
                let timeout = TimeoutFuture::new((deadline - started).max(1.0) as u32);
                futures_util::pin_mut!(request, timeout);
                match futures_util::future::select(request, timeout).await {
                    futures_util::future::Either::Left((result, _)) => result,
                    futures_util::future::Either::Right(_) => Err(PeerError::TimedOut),
                }
            };
            initial.check()?;
            let credentials = if monotonic_ms()? >= deadline {
                Err(PeerError::TimedOut)
            } else {
                credentials
            };
            let credentials = match credentials {
                Ok(credentials) => credentials,
                Err(PeerError::RelayUnavailable | PeerError::TimedOut)
                    if mode == PeerPathMode::DirectPreferred =>
                {
                    return Self::new_with_lease(
                        sdk,
                        permit,
                        identity,
                        lease,
                        stun,
                        PeerPathMode::DirectOnly,
                    );
                }
                Err(problem) => return Err(problem),
            };
            let mut ice = managed_ice_configuration(&credentials)?;
            ice.servers.extend(stun.servers);
            let ice = TrustedIceConfiguration::from_trusted_deployment_config(ice.servers)?;
            let mut peer = Self::new_with_lease(sdk, permit, identity, lease, ice, mode)?;
            peer.authority
                .borrow_mut()
                .authorize_turn(&credentials, started)?;
            peer.turn_credentials = Some(credentials);
            Ok(peer)
        }

        pub fn cancellation(&self) -> PeerCancellation {
            PeerCancellation {
                cancelled: self.cancelled.clone(),
                peer: self.peer.clone(),
                expiry_timer: self.expiry_timer,
                data: self.data.clone(),
                diagnostics: self.diagnostics.clone(),
            }
        }

        pub fn record_failure(&self, problem: &PeerError) -> ConnectionFailure {
            let failure = problem.diagnostic_failure_for_setup(self.permit.claims().is_setup());
            self.diagnostics.failure(failure);
            failure
        }

        fn turn_failure(&self, stage: ConnectionStage, problem: PeerError) -> PeerError {
            // Optional availability failures may be retried by the caller.
            // Preserve the first fatal operation before cleanup closes peers.
            if !matches!(problem, PeerError::RelayUnavailable | PeerError::TimedOut) {
                self.diagnostics.failure_at(
                    stage,
                    problem.diagnostic_failure_for_setup(self.permit.claims().is_setup()),
                );
            }
            problem
        }

        pub fn data_channels(&self) -> Result<BrowserDataChannels, PeerError> {
            self.ensure_live()?;
            if !self.proof_complete.get() {
                return Err(PeerError::EndpointMismatch);
            }
            self.data
                .check_deadlines()
                .map_err(|_| PeerError::BrowserOperation)?;
            Ok(self.data.clone())
        }

        pub fn connection_generation(&self) -> u64 {
            self.permit.claims().connection_generation
        }

        /// The caller receives the actual remote track and owns presentation.
        /// No display or connected status is manufactured by this core.
        pub fn on_remote_track(
            &mut self,
            callback: impl FnMut(web_sys::MediaStreamTrack) + 'static,
        ) {
            let callback = Rc::new(RefCell::new(callback));
            let peer = self.peer.clone();
            let authority = self.authority.clone();
            let cancelled = self.cancelled.clone();
            let mode = self.mode;
            let proof_complete = self.proof_complete.clone();
            let diagnostics = self.diagnostics.clone();
            let handler = Closure::wrap(Box::new(move |event: RtcTrackEvent| {
                let track = event.track();
                track.set_enabled(false);
                let permission = match track.kind().as_str() {
                    "video" => Permission::View,
                    "audio" => Permission::Audio,
                    _ => {
                        track.stop();
                        close_peer(&peer, &cancelled);
                        return;
                    }
                };
                if check_authority(&peer, &cancelled, &authority).is_err()
                    || !authority
                        .borrow()
                        .permit
                        .claims()
                        .permissions
                        .contains(&(permission as i32))
                {
                    track.stop();
                    close_peer(&peer, &cancelled);
                    return;
                }
                let peer = peer.clone();
                let authority = authority.clone();
                let cancelled = cancelled.clone();
                let callback = callback.clone();
                let proof_complete = proof_complete.clone();
                let diagnostics = diagnostics.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    // ontrack fires when the answer is installed, before ICE
                    // and endpoint proof complete. The owning setup operation
                    // and signed lease bound this wait; a separate 10s timer
                    // must not close a still-authorized connection attempt.
                    loop {
                        if let Err(problem) = check_authority(&peer, &cancelled, &authority) {
                            if problem != PeerError::Cancelled {
                                diagnostics.failure_at(
                                    ConnectionStage::TrackAwaitAuthorization,
                                    problem.diagnostic_failure_for_setup(
                                        authority.borrow().permit.claims().is_setup(),
                                    ),
                                );
                            }
                            track.stop();
                            return;
                        }
                        if peer.connection_state() == RtcPeerConnectionState::Connected
                            && proof_complete.get()
                            && authority.borrow().path.ready()
                        {
                            break;
                        }
                        TimeoutFuture::new(POLL_INTERVAL_MS).await;
                    }
                    let deadline = authority
                        .borrow()
                        .permit_deadline_ms
                        .min(authority.borrow().endpoint_deadline_ms);
                    let result = bounded_live(
                        selected_path_from_peer(&peer),
                        deadline,
                        &peer,
                        &cancelled,
                        &authority,
                    )
                    .await
                    .and_then(|path| {
                        verify_selected_paths(
                            mode,
                            &authority.borrow().permit.claims().paths,
                            &[path],
                        )
                    });
                    if result.is_err() || check_authority(&peer, &cancelled, &authority).is_err() {
                        track.stop();
                        close_peer(&peer, &cancelled);
                        return;
                    }
                    track.set_enabled(true);
                    callback.borrow_mut()(track);
                });
            }) as Box<dyn FnMut(RtcTrackEvent)>);
            self.peer
                .set_ontrack(Some(handler.as_ref().unchecked_ref()));
            self.track_handler = Some(handler);
        }

        /// Gathers and publishes a signed SDP offer. The browser controller is
        /// offer-only; host answering remains the responsibility of the real host.
        pub async fn create_and_publish_offer(&mut self, timeout_ms: u32) -> Result<(), PeerError> {
            self.ensure_live()?;
            if self.offer_published {
                return Err(PeerError::OfferRequired);
            }
            let deadline = self.renewable_operation_deadline(timeout_ms)?;
            let offer = self
                .await_bounded(
                    async {
                        JsFuture::from(self.peer.create_offer())
                            .await
                            .map_err(|_| PeerError::BrowserOperation)
                    },
                    deadline,
                )
                .await?;
            let offer = rtc_session_description_init(offer, RtcSdpType::Offer)
                .map_err(|_| PeerError::BrowserOperation)?;
            restrict_local_description(&offer, self.permit.claims())?;
            self.await_bounded(
                async {
                    JsFuture::from(self.peer.set_local_description(&offer))
                        .await
                        .map_err(|_| PeerError::BrowserOperation)
                },
                deadline,
            )
            .await?;
            self.diagnostics.mark(ConnectionStage::LocalDescriptionSet);
            if !self.trickle_enabled() {
                self.wait_for_ice_gathering(deadline).await?;
            }
            let local = self
                .peer
                .local_description()
                .ok_or(PeerError::BrowserOperation)?;
            let description = web_description("offer", local.sdp(), self.permit.claims())?;
            let network_generation = self.network_generation;
            self.publish_description(description, network_generation, deadline)
                .await?;
            self.offer_published = true;
            Ok(())
        }

        /// Restarts ICE after the caller observes a real network change. The
        /// new offer carries a strictly increasing signaling network generation;
        /// a failed restart closes the previous transport fail-closed.
        pub async fn restart_ice_and_publish_offer(
            &mut self,
            timeout_ms: u32,
        ) -> Result<u64, PeerError> {
            self.ensure_live()?;
            if !self.offer_published || !self.remote_answer_set {
                return Err(PeerError::OfferRequired);
            }
            self.diagnostics.mark(ConnectionStage::IceRestart);
            let next_generation = next_network_generation(self.network_generation)?;
            for receiver in self.peer.get_receivers().iter() {
                if let Ok(receiver) = receiver.dyn_into::<RtcRtpReceiver>() {
                    receiver.track().set_enabled(false);
                }
            }
            let result = self
                .restart_ice_and_publish_offer_inner(timeout_ms, next_generation)
                .await;
            if result.is_err() {
                close_peer(&self.peer, &self.cancelled);
            }
            result.map(|()| next_generation)
        }

        async fn restart_ice_and_publish_offer_inner(
            &mut self,
            timeout_ms: u32,
            next_generation: u64,
        ) -> Result<(), PeerError> {
            let deadline = self.renewable_operation_deadline(timeout_ms)?;
            if self.turn_credentials.is_some() {
                self.authority.borrow_mut().path.turn_bound = false;
                self.refresh_turn_credentials(next_generation, true, deadline)
                    .await?;
            }
            let options = RtcOfferOptions::new();
            options.set_ice_restart(true);
            let offer = self
                .await_bounded(
                    async {
                        JsFuture::from(self.peer.create_offer_with_rtc_offer_options(&options))
                            .await
                            .map_err(|_| PeerError::BrowserOperation)
                    },
                    deadline,
                )
                .await?;
            let offer = rtc_session_description_init(offer, RtcSdpType::Offer)
                .map_err(|_| PeerError::BrowserOperation)?;
            restrict_local_description(&offer, self.permit.claims())?;
            self.await_bounded(
                async {
                    JsFuture::from(self.peer.set_local_description(&offer))
                        .await
                        .map_err(|_| PeerError::BrowserOperation)
                },
                deadline,
            )
            .await?;
            self.diagnostics.mark(ConnectionStage::LocalDescriptionSet);
            if !self.trickle_enabled() {
                self.wait_for_ice_gathering(deadline).await?;
            }
            let local = self
                .peer
                .local_description()
                .ok_or(PeerError::BrowserOperation)?;
            let description = web_description("offer", local.sdp(), self.permit.claims())?;
            self.publish_description(description, next_generation, deadline)
                .await?;
            self.remote_answer_set = false;
            Ok(())
        }

        /// Fetches peer signals through the SDK verifier and applies a signed
        /// SDP answer. Candidate-only trickle is rejected until the protocol
        /// carries browser-native candidate strings.
        pub async fn receive_and_apply_answer(&mut self) -> Result<(), PeerError> {
            self.receive_and_apply_answer_with_timeout(MAX_OPERATION_MS)
                .await
        }

        /// Poll the signaling endpoint for a bounded interval so pending host
        /// renewals can be serviced while an ICE restart has no answer yet.
        pub async fn receive_and_apply_answer_with_timeout(
            &mut self,
            timeout_ms: u32,
        ) -> Result<(), PeerError> {
            self.ensure_live()?;
            if !self.offer_published {
                return Err(PeerError::OfferRequired);
            }
            let deadline = self.renewable_operation_deadline(MAX_OPERATION_MS)?;
            // Answer polling begins before a TURN peer binding exists. Renew
            // the allocation independently instead of waiting for that binding.
            self.maintain_turn_allocation_before(deadline).await?;
            let poll_deadline = self.renewable_operation_deadline(timeout_ms)?;
            self.publish_local_ice(poll_deadline).await?;
            let signals = match bounded_live(
                async {
                    let sdk = self.sdk.lock().await;
                    sdk.peer_signals(&self.identity, &self.permit, &mut self.cursor)
                        .await
                        .map_err(|_| PeerError::SignalRejected)
                },
                poll_deadline,
                &self.peer,
                &self.cancelled,
                &self.authority,
            )
            .await
            {
                Ok(signals) => signals,
                Err(PeerError::TimedOut) => {
                    self.ensure_live()?;
                    return Err(PeerError::AnswerRequired);
                }
                Err(problem) => return Err(problem),
            };
            let mut saw_answer = false;
            for signal in signals {
                self.ensure_live()?;
                let description = signal
                    .clone()
                    .description
                    .ok_or(PeerError::UnsupportedTrickleSignal)?;
                if description.kind != "answer" {
                    return Err(PeerError::AnswerRequired);
                }
                let offer_sequence = description
                    .in_reply_to_sequence
                    .ok_or(PeerError::SignalRejected)?;
                if !answer_matches_current_offer(self.local_offer_sequence, offer_sequence)? {
                    continue;
                }
                self.diagnostics
                    .signal(ConnectionStage::SignalConsumed, &signal);
                if signal.ice.is_some()
                    && self.remote_answer_sequence == signal.description_sequence()
                {
                    self.apply_remote_ice(&signal).await?;
                    saw_answer = true;
                    continue;
                }
                let remote = rtc_description(&description, self.permit.claims())?;
                self.input_state.borrow_mut().scroll_supported = description
                    .sdp
                    .lines()
                    .any(|line| line == "a=nestlink-scroll:120");
                if self.turn_credentials.is_some() {
                    self.remote_candidate_addresses =
                        managed_candidate_addresses(self.mode, &description.sdp)?;
                    self.remote_network_generation = signal.network_generation;
                }
                self.await_bounded(
                    async {
                        JsFuture::from(self.peer.set_remote_description(&remote))
                            .await
                            .map_err(|_| PeerError::BrowserOperation)
                    },
                    self.operation_deadline(MAX_OPERATION_MS)?,
                )
                .await?;
                self.remote_answer_set = true;
                self.diagnostics
                    .signal(ConnectionStage::RemoteDescriptionSet, &signal);
                self.remote_answer_sequence = signal.description_sequence();
                self.remote_ice.reset();
                self.apply_remote_ice(&signal).await?;
                saw_answer = true;
            }
            if saw_answer {
                // Path checking must start as soon as the verified answer is
                // installed. TURN binding is serviced by the path wait; it
                // cannot hold the direct path behind a separate polling loop.
                Ok(())
            } else {
                Err(PeerError::AnswerRequired)
            }
        }

        /// Returns a path only after WebRTC reports a connected peer and the
        /// selected candidate pair has been checked against the signed permit.
        pub async fn wait_for_verified_path(
            &mut self,
            timeout_ms: u32,
        ) -> Result<SelectedPath, PeerError> {
            match self
                .wait_for_verified_path_or_network_change(timeout_ms, || false)
                .await?
            {
                Some(path) => Ok(path),
                None => Err(PeerError::TimedOut),
            }
        }

        /// Wait for an authorized path unless a newer browser connectivity
        /// event arrived while this ICE restart was being answered. Returning
        /// `None` leaves the peer open so the caller can publish one coalesced
        /// restart for the newest network state.
        pub async fn wait_for_verified_path_or_network_change(
            &mut self,
            timeout_ms: u32,
            mut network_changed: impl FnMut() -> bool,
        ) -> Result<Option<SelectedPath>, PeerError> {
            self.ensure_live()?;
            if !self.remote_answer_set {
                return Err(PeerError::AnswerRequired);
            }
            let deadline = self.renewable_operation_deadline(timeout_ms)?;
            self.diagnostics.mark_once(ConnectionStage::PathChecking);
            // Keep the WebRTC wait independent of `self` so lease renewal can
            // be consumed while the browser is waiting for the candidate pair.
            let peer = self.peer.clone();
            let cancelled = self.cancelled.clone();
            let authority = self.authority.clone();
            let paths = self.permit.claims().paths.clone();
            let mut operation = Box::pin(wait_for_selected_path(
                &peer, &cancelled, &authority, self.mode, &paths, deadline,
            ));
            let mut next_ice_sample_ms = 0.0;
            let result = loop {
                if monotonic_ms().is_ok_and(|now| now >= next_ice_sample_ms) {
                    self.sample_ice_checks().await;
                    next_ice_sample_ms = monotonic_ms().unwrap_or(deadline) + 1_000.0;
                }
                if network_changed() {
                    break Ok(None);
                }
                if let Err(problem) = self.ensure_live() {
                    break Err(problem);
                }
                let remaining = match monotonic_ms() {
                    Ok(now) => deadline - now,
                    Err(problem) => break Err(problem),
                };
                if remaining <= 0.0 {
                    break Err(PeerError::TimedOut);
                }
                let wait_ms = remaining.min(f64::from(POLL_INTERVAL_MS)).max(1.0) as u32;
                match select(operation, Box::pin(TimeoutFuture::new(wait_ms))).await {
                    futures_util::future::Either::Left((result, _)) => {
                        if network_changed() {
                            break Ok(None);
                        }
                        break result.map(Some);
                    }
                    futures_util::future::Either::Right((_, pending)) => {
                        operation = pending;
                        if self.trickle_enabled() {
                            match self.receive_and_apply_answer_with_timeout(1_000).await {
                                Ok(()) | Err(PeerError::AnswerRequired) => {}
                                Err(problem) => break Err(problem),
                            }
                        }
                        if network_changed() {
                            break Ok(None);
                        }
                        if let Err(problem) = self.renew_from_host_before(deadline).await {
                            break Err(problem);
                        }
                        if let Err(problem) = self.maintain_turn_before(deadline).await {
                            break Err(problem);
                        }
                    }
                }
            };
            match result {
                Ok(Some(_)) => {
                    self.resume_tracks()?;
                    self.diagnostics.mark(ConnectionStage::PathVerified);
                }
                Ok(None) => {}
                Err(ref problem) => {
                    if *problem == PeerError::TimedOut {
                        self.diagnostics.failure(ConnectionFailure::IceCheckTimeout);
                    } else {
                        self.record_failure(problem);
                    }
                    self.sample_ice_checks().await;
                    close_peer(&self.peer, &self.cancelled);
                }
            }
            result
        }

        async fn sample_ice_checks(&self) {
            // Best effort and bounded independently of authorization. Missing
            // diagnostics must neither delay setup nor change its result.
            let stats = Box::pin(JsFuture::from(self.peer.get_stats()));
            if let futures_util::future::Either::Left((Ok(value), _)) =
                select(stats, Box::pin(TimeoutFuture::new(100))).await
                && let Ok(report) = value.dyn_into::<RtcStatsReport>()
                && let Ok(snapshot) = ice_checks_from_report(&report)
            {
                self.diagnostics.ice_checks(snapshot);
            }
        }

        /// Consume a host signature and renew through the authenticated SDK.
        /// A peer message alone can never extend the authorization deadline.
        pub async fn complete_endpoint_proof(&mut self) -> Result<(), PeerError> {
            self.ensure_live()?;
            if self.proof_complete.get() {
                return Ok(());
            }
            if let Err(problem) = self.complete_endpoint_proof_inner().await {
                if problem == PeerError::TimedOut {
                    self.diagnostics.failure(ConnectionFailure::ProofTimeout);
                } else {
                    self.record_failure(&problem);
                }
                self.cancellation().cancel();
                return Err(problem);
            }
            self.diagnostics.mark_once(ConnectionStage::EndpointProved);
            // The host may publish its next-lease signature as soon as the
            // endpoint proof completes. Consume it before any post-proof
            // display wait can reach the original short permit deadline.
            if let Err(problem) = self.renew_from_host().await {
                self.cancellation().cancel();
                return Err(problem);
            }
            let deadline = self.operation_deadline(MAX_OPERATION_MS)?;
            while self.permit.claims().is_setup() {
                if let Err(problem) = self.renew_from_host_before(deadline).await {
                    self.cancellation().cancel();
                    return Err(problem);
                }
                if self.permit.claims().is_setup() {
                    self.wait_tick(deadline).await?;
                }
            }
            self.diagnostics
                .mark_once(ConnectionStage::RunningAuthorized);
            Ok(())
        }

        /// Wait for the host's post-proof input layout. A view-only permit
        /// cannot obtain an input sender or accept an input layout.
        pub async fn wait_for_input_layout(
            &mut self,
            timeout_ms: u32,
        ) -> Result<Option<PeerInputLayout>, PeerError> {
            self.ensure_live()?;
            if !self
                .permit
                .claims()
                .permissions
                .contains(&(Permission::Input as i32))
            {
                return Ok(None);
            }
            if !self.proof_complete.get() {
                return Err(PeerError::EndpointMismatch);
            }
            let deadline = self.renewable_operation_deadline(timeout_ms)?;
            loop {
                self.ensure_live()?;
                self.renew_from_host_before(deadline).await?;
                self.maintain_turn_before(deadline).await?;
                if let Some(layout) = self.input_layout()? {
                    return Ok(Some(layout));
                }
                self.wait_tick(deadline).await?;
            }
        }

        /// Only the fully validated, ACKed local approval subset is exposed.
        pub async fn wait_for_display_catalog(
            &mut self,
            timeout_ms: u32,
        ) -> Result<super::PeerDisplaySnapshot, PeerError> {
            self.ensure_live()?;
            if !self.proof_complete.get() {
                return Err(PeerError::EndpointMismatch);
            }
            let deadline = self.renewable_operation_deadline(timeout_ms)?;
            loop {
                self.renew_from_host_before(deadline).await?;
                self.maintain_turn_before(deadline).await?;
                if let Some(snapshot) = self.display_snapshot()? {
                    return Ok(snapshot);
                }
                self.wait_tick(deadline).await?;
            }
        }

        pub async fn wait_for_display_selection(
            &mut self,
            timeout_ms: u32,
        ) -> Result<super::PeerDisplaySnapshot, PeerError> {
            self.ensure_live()?;
            let deadline = self.renewable_operation_deadline(timeout_ms)?;
            loop {
                self.renew_from_host_before(deadline).await?;
                self.maintain_turn_before(deadline).await?;
                if let Some(snapshot) = self.display_snapshot()?
                    && snapshot.selected.is_some()
                    && snapshot.pending_source.is_none()
                {
                    self.diagnostics.mark(ConnectionStage::DisplaySelected);
                    return Ok(snapshot);
                }
                self.wait_tick(deadline).await?;
            }
        }

        pub fn display_snapshot(&self) -> Result<Option<super::PeerDisplaySnapshot>, PeerError> {
            self.ensure_live()?;
            if let Some(deadline) = self.display_deadline.get()
                && monotonic_ms()? >= deadline
            {
                self.cancellation().cancel();
                return Err(PeerError::TimedOut);
            }
            Ok(self.display_state.borrow().snapshot())
        }

        /// One selection may be outstanding. Release keys on the old epoch
        /// before the ordered Select, and block input until the exact ACK.
        pub fn select_display(&self, source: u32) -> Result<bool, PeerError> {
            let select = || {
                self.ensure_live()?;
                if !self.proof_complete.get() || !self.authority.borrow().path.ready() {
                    return Err(PeerError::EndpointMismatch);
                }
                let snapshot = self.display_snapshot()?.ok_or(PeerError::SignalRejected)?;
                if snapshot.pending_source.is_none()
                    && snapshot
                        .selected
                        .as_ref()
                        .is_some_and(|value| value.source == source)
                {
                    return Ok(false);
                }
                let deadline = self.operation_deadline(5_000)?;
                if self.input_layout()?.is_some() {
                    self.input_sender()?.send(BrowserInputEvent::ReleaseAll)?;
                }
                let envelope = self.display_state.borrow_mut().select(source)?;
                let mut input = self.input_state.borrow_mut();
                input.suspended = true;
                input.pending_layout = None;
                drop(input);
                self.display_deadline.set(Some(deadline));
                // The host pins the permit carried by this Select. A renewal
                // may finish before its Layout/Selected return, so retain only
                // this transaction's exact permit until its ACK or deadline.
                let permit = self.authority.borrow().permit.clone();
                *self.display_permit.borrow_mut() = Some(permit.clone());
                send_display_control(&self.control_channel, &envelope, permit.claims())?;
                Ok(true)
            };
            let result = select();
            if result.is_err() {
                self.display_permit.borrow_mut().take();
                self.display_deadline.set(None);
                self.cancellation().cancel();
            }
            result
        }

        pub fn input_layout(&self) -> Result<Option<PeerInputLayout>, PeerError> {
            self.ensure_live()?;
            let state = self.input_state.borrow();
            Ok((!state.suspended).then_some(state.layout).flatten())
        }

        pub fn input_sender(&self) -> Result<PeerInputSender, PeerError> {
            self.ensure_live()?;
            if !self.proof_complete.get()
                || !self
                    .permit
                    .claims()
                    .permissions
                    .contains(&(Permission::Input as i32))
                || self.input_state.borrow().layout.is_none()
                || self.input_state.borrow().suspended
            {
                return Err(PeerError::InvalidPermit);
            }
            Ok(PeerInputSender {
                peer: self.peer.clone(),
                channel: self.control_channel.clone(),
                cancelled: self.cancelled.clone(),
                authority: self.authority.clone(),
                proof_complete: self.proof_complete.clone(),
                state: self.input_state.clone(),
            })
        }

        async fn complete_endpoint_proof_inner(&mut self) -> Result<(), PeerError> {
            let path = self.wait_for_verified_path(10_000).await?;
            let path = match path {
                SelectedPath::Direct => Path::Direct,
                SelectedPath::Relay => Path::Relay,
                SelectedPath::Mixed => return Err(PeerError::SelectedPathRejected),
            };
            let host_key = self
                .await_bounded(
                    async {
                        self.sdk
                            .lock()
                            .await
                            .remote_peer_key(&self.permit, &self.identity)
                            .await
                            .map_err(|_| PeerError::EndpointMismatch)
                    },
                    self.operation_deadline(MAX_OPERATION_MS)?,
                )
                .await?;
            let deadline = self.operation_deadline(3_000)?;
            let claims = self.permit.claims();
            let binding = SessionBinding {
                deployment_id: claims.deployment_id.clone(),
                security_epoch: claims.security_epoch,
                session_id: claims.session_id.clone(),
                account_id: claims.account_id.clone(),
                controller_device_id: claims.controller_device_id.clone(),
                host_device_id: claims.host_device_id.clone(),
                controller_key_sha256: claims
                    .controller_key_sha256
                    .as_slice()
                    .try_into()
                    .map_err(|_| PeerError::InvalidPermit)?,
                host_key_sha256: claims
                    .host_key_sha256
                    .as_slice()
                    .try_into()
                    .map_err(|_| PeerError::InvalidPermit)?,
                resource_id: claims.resource_id.clone(),
                policy_revision: claims.policy_revision,
                connection_generation: claims.connection_generation,
                capability_sha256: claims
                    .capability_sha256
                    .as_slice()
                    .try_into()
                    .map_err(|_| PeerError::InvalidPermit)?,
                granted_permissions: claims
                    .permissions
                    .iter()
                    .map(|value| Permission::try_from(*value).map_err(|_| PeerError::InvalidPermit))
                    .collect::<Result<Vec<_>, _>>()?,
                supported_capabilities: claims.required_capabilities.clone(),
                local_paths: PathSet::from_wire(&claims.paths)
                    .map_err(|_| PeerError::InvalidPermit)?,
            };
            let cap_deadline_ms = {
                let authority = self.authority.borrow();
                authority
                    .endpoint_deadline_ms
                    .min(authority.permit_deadline_ms) as u64
            };
            let now = ClockSample {
                monotonic_ms: monotonic_ms()? as u64,
                unix_ms: now_ms()?,
            };
            let mut session = Session::activate_with_retained_deadline(
                self.permit.clone(),
                binding,
                path,
                now,
                cap_deadline_ms,
            )
            .map_err(|_| PeerError::InvalidPermit)?;
            // Retain the authority's clock-regression and independent-expiry
            // checks before signing or sending any endpoint proof.
            self.ensure_live()?;
            let local = session.proof_transcript();
            let signature = self
                .identity
                .identity
                .prove(&local)
                .map_err(|_| PeerError::EndpointMismatch)?;
            session
                .confirm_endpoint(
                    EndpointRole::Controller,
                    &self.identity.identity.public_key(),
                    &signature,
                    monotonic_ms()? as u64,
                )
                .map_err(|_| PeerError::EndpointMismatch)?;
            self.send_control(
                self.proof_message(NativeProof {
                    transcript: Some(local.clone()),
                    signature,
                    peer_transcript_signature: Vec::new(),
                }),
                deadline,
            )
            .await?;
            let WebRtcControl::EndpointProof { proof, .. } =
                self.receive_proof_message(deadline).await?
            else {
                return Err(PeerError::SignalRejected);
            };
            let remote = proof.transcript.as_ref().ok_or(PeerError::SignalRejected)?;
            let mut expected = local.clone();
            expected.challenge = remote.challenge.clone();
            if &expected != remote || remote.challenge.len() != 32 {
                return Err(PeerError::EndpointMismatch);
            }
            verify_endpoint_proof(remote, &host_key, &proof.signature)
                .map_err(|_| PeerError::EndpointMismatch)?;
            session
                .confirm_endpoint(
                    EndpointRole::Host,
                    &host_key,
                    &proof.peer_transcript_signature,
                    monotonic_ms()? as u64,
                )
                .map_err(|_| PeerError::EndpointMismatch)?;
            let response = NativeProof {
                transcript: Some(remote.clone()),
                signature: self
                    .identity
                    .identity
                    .prove(remote)
                    .map_err(|_| PeerError::EndpointMismatch)?,
                peer_transcript_signature: Vec::new(),
            };
            self.acceptance_expected.set(true);
            self.send_control(self.proof_message(response), deadline)
                .await?;
            if !matches!(
                self.receive_proof_message(deadline).await?,
                WebRtcControl::EndpointProofAccepted { .. }
            ) {
                return Err(PeerError::SignalRejected);
            }
            self.ensure_live()?;
            session
                .check_clock(ClockSample {
                    monotonic_ms: monotonic_ms()? as u64,
                    unix_ms: now_ms()?,
                })
                .map_err(|_| PeerError::Expired)?;
            self.authority.borrow_mut().proved_session = Some(session);
            self.proof_complete.set(true);
            let catalog = self.pending_catalog.borrow_mut().take();
            for message in catalog {
                apply_display_control(
                    &self.control_channel,
                    &self.authority,
                    &self.input_state,
                    &self.display_state,
                    &self.display_deadline,
                    &self.display_permit,
                    message,
                )?;
            }
            Ok(())
        }

        fn proof_message(&self, proof: NativeProof) -> WebRtcControl {
            let claims = self.permit.claims();
            WebRtcControl::EndpointProof {
                schema_version: claims.schema_version,
                session_id: claims.session_id.clone(),
                connection_generation: claims.connection_generation,
                lease_sequence: claims.lease_sequence,
                proof,
            }
        }

        async fn send_control(
            &self,
            message: WebRtcControl,
            deadline: f64,
        ) -> Result<(), PeerError> {
            loop {
                self.ensure_live()?;
                if self.control_channel.ready_state() == web_sys::RtcDataChannelState::Open {
                    break;
                }
                self.wait_tick(deadline).await?;
            }
            let bytes = message
                .encode_validated(self.permit.claims())
                .map_err(|_| PeerError::SignalRejected)?;
            self.control_channel
                .send_with_u8_array(&bytes)
                .map_err(|_| PeerError::BrowserOperation)?;
            self.ensure_live()
        }

        async fn receive_proof_message(&self, deadline: f64) -> Result<WebRtcControl, PeerError> {
            loop {
                self.ensure_live()?;
                if let Some(message) = self.proof_messages.borrow_mut().pop_front() {
                    if monotonic_ms()? >= deadline {
                        return Err(PeerError::TimedOut);
                    }
                    message
                        .validate(self.permit.claims())
                        .map_err(|_| PeerError::SignalRejected)?;
                    return Ok(message);
                }
                self.wait_tick(deadline).await?;
            }
        }

        pub async fn renew_from_host(&mut self) -> Result<bool, PeerError> {
            self.renew_from_host_before(f64::INFINITY).await
        }

        async fn renew_from_host_before(&mut self, deadline_limit: f64) -> Result<bool, PeerError> {
            self.ensure_live()?;
            let Some(message) = self.pending_renewal.borrow_mut().take() else {
                return Ok(false);
            };
            message
                .validate(self.permit.claims())
                .map_err(|_| PeerError::InvalidPermit)?;
            let WebRtcControl::HostRenewalSignature { signature, .. } = message else {
                return Err(PeerError::SignalRejected);
            };
            let request_started_ms = monotonic_ms()?;
            let deadline = self
                .operation_deadline(MAX_OPERATION_MS)?
                .min(deadline_limit);
            let permit = self
                .await_bounded(
                    async {
                        let sdk = self.sdk.lock().await;
                        let view = sdk
                            .remote(&self.permit.claims().session_id)
                            .await
                            .map_err(|_| PeerError::SignalRejected)?;
                        sdk.renew_permit(&self.identity, &view, &self.permit, signature)
                            .await
                            .map_err(|_| PeerError::InvalidPermit)
                    },
                    deadline,
                )
                .await?;
            let result = self
                .authority
                .borrow_mut()
                .replace(permit.clone(), request_started_ms);
            if result.is_err() {
                self.cancellation().cancel();
            }
            result?;
            self.permit = permit;
            if self.authority.borrow().path.selected == Some(SelectedPath::Direct) {
                self.disable_optional_turn()?;
            }
            if self.turn_credentials.is_some() {
                self.pause_tracks();
                self.authority.borrow_mut().path.turn_bound = false;
                self.authority.borrow_mut().turn_binding_deadline_ms = None;
                if let Err(problem) = async {
                    self.refresh_turn_credentials(self.network_generation, false, deadline)
                        .await?;
                    self.await_turn_binding(deadline).await
                }
                .await
                {
                    self.cancellation().cancel();
                    return Err(problem);
                }
                self.resume_tracks()?;
            }
            Ok(true)
        }

        /// Renew the allocation independently of permit renewal. Node leases
        /// may bound the credentials to a shorter lifetime than the permit.
        pub async fn maintain_turn(&mut self) -> Result<(), PeerError> {
            self.maintain_turn_before(f64::INFINITY).await
        }

        async fn maintain_turn_before(&mut self, deadline_limit: f64) -> Result<(), PeerError> {
            let result = async {
                self.maintain_turn_allocation_before(deadline_limit).await?;
                if self.turn_credentials.is_none() {
                    return Ok(());
                }
                let deadline = self
                    .renewable_operation_deadline(MAX_OPERATION_MS)?
                    .min(deadline_limit);
                if !self.authority.borrow().path.turn_bound {
                    self.pause_tracks();
                    self.await_turn_binding(deadline).await?;
                    self.resume_tracks()?;
                }
                Ok(())
            }
            .await;
            if result.is_err() {
                self.cancellation().cancel();
            }
            result
        }

        /// Allocation renewal does not require a remote SDP or peer binding.
        /// Gathering and answer polling must service this shorter node lease.
        async fn maintain_turn_allocation_before(
            &mut self,
            deadline_limit: f64,
        ) -> Result<(), PeerError> {
            self.ensure_live()?;
            if self.authority.borrow().path.selected == Some(SelectedPath::Direct) {
                self.disable_optional_turn()?;
                self.resume_tracks()?;
                return Ok(());
            }
            let Some(credentials) = &self.turn_credentials else {
                return Ok(());
            };
            let now = now_ms()?;
            let monotonic_now = monotonic_ms()?;
            let refresh = credentials.claims().expires_at_unix_ms.saturating_sub(now) <= 3_000
                || self
                    .authority
                    .borrow()
                    .turn_deadline_ms
                    .is_some_and(|limit| limit - monotonic_now <= 3_000.0);
            let deadline = self
                .renewable_operation_deadline(MAX_OPERATION_MS)?
                .min(deadline_limit);
            if refresh {
                self.refresh_turn_credentials(self.network_generation, false, deadline)
                    .await?;
            }
            Ok(())
        }

        async fn refresh_turn_credentials(
            &mut self,
            network_generation: u64,
            replace: bool,
            deadline: f64,
        ) -> Result<(), PeerError> {
            let allocation_id = if replace {
                uuid::Uuid::new_v4().to_string()
            } else {
                self.turn_credentials
                    .as_ref()
                    .ok_or(PeerError::RelayUnavailable)?
                    .claims()
                    .allocation_id
                    .clone()
            };
            let started = monotonic_ms()?;
            let credentials = self
                .await_bounded(
                    async {
                        self.sdk
                            .lock()
                            .await
                            .reserve_turn_credentials(
                                &self.identity,
                                &self.permit,
                                &allocation_id,
                                network_generation,
                                now_ms()?,
                            )
                            .await
                            .map_err(turn_sdk_error)
                    },
                    deadline,
                )
                .await
                .map_err(|problem| {
                    self.turn_failure(ConnectionStage::TurnCredentialsRefresh, problem)
                })?;
            let mut ice = managed_ice_configuration(&credentials)?;
            ice.servers.extend(self.direct_ice.servers.iter().cloned());
            let configuration = rtc_configuration(&ice, self.mode, &self.permit.claims().paths)?;
            self.peer
                .set_configuration_with_configuration(&configuration)
                .map_err(|_| PeerError::BrowserOperation)?;
            self.authority
                .borrow_mut()
                .authorize_turn(&credentials, started)?;
            self.turn_credentials = Some(credentials);
            Ok(())
        }

        async fn await_turn_binding(&mut self, deadline: f64) -> Result<(), PeerError> {
            loop {
                if self.poll_turn_binding(deadline).await? {
                    return Ok(());
                }
                // An optional binding never delays the next ICE/path check.
                // Relay paths still cannot be selected until it is complete.
                if !self.authority.borrow().path.requires_turn() {
                    return Ok(());
                }
                self.wait_tick(deadline).await?;
            }
        }

        async fn poll_turn_binding(&mut self, deadline: f64) -> Result<bool, PeerError> {
            self.ensure_live()?;
            if self.mode == PeerPathMode::DirectPreferred
                && self.peer.connection_state() == RtcPeerConnectionState::Connected
            {
                match self
                    .await_bounded(selected_path_from_peer(&self.peer), deadline)
                    .await
                {
                    Ok(SelectedPath::Direct) => {
                        verify_live_path(&self.authority, SelectedPath::Direct)?;
                        self.disable_optional_turn()?;
                        return Ok(true);
                    }
                    Ok(_) | Err(PeerError::NoSelectedPath) => {}
                    Err(problem) => return Err(problem),
                }
            }
            self.maintain_turn_allocation_before(deadline).await?;
            if self.turn_credentials.is_none() {
                return Ok(true);
            }
            if self.local_candidate_addresses.is_empty()
                || self.remote_candidate_addresses.is_empty()
            {
                if self.mode == PeerPathMode::RelayOnly {
                    return Err(PeerError::RelayUnavailable);
                }
                return Ok(false);
            }
            let request_deadline = if self.mode == PeerPathMode::DirectPreferred {
                deadline.min(monotonic_ms()? + 3_000.0)
            } else {
                deadline
            };
            let state = self
                .await_bounded(
                    async {
                        self.sdk
                            .lock()
                            .await
                            .turn_binding_state(&self.identity, &self.permit)
                            .await
                            .map_err(turn_sdk_error)
                    },
                    request_deadline,
                )
                .await;
            let state = match state {
                Ok(state) => state,
                Err(PeerError::RelayUnavailable | PeerError::TimedOut)
                    if self.mode == PeerPathMode::DirectPreferred =>
                {
                    return Ok(false);
                }
                Err(problem) => {
                    return Err(self.turn_failure(ConnectionStage::TurnBindingRead, problem));
                }
            };
            if let Some(signed) = state.binding {
                let binding: nestlink_protocol::TurnPeerBindingClaims =
                    nestlink_protocol::decode_bounded(&signed.claims, TURN_BINDING_BYTES).map_err(
                        |_| {
                            self.turn_failure(
                                ConnectionStage::TurnBindingValidate,
                                PeerError::SignalRejected,
                            )
                        },
                    )?;
                let credentials = self
                    .turn_credentials
                    .as_ref()
                    .ok_or(PeerError::RelayUnavailable)?;
                let fresh = validate_managed_binding(
                    &binding,
                    credentials.claims(),
                    self.remote_network_generation,
                    &self.local_candidate_addresses,
                    &self.remote_candidate_addresses,
                    now_ms()?,
                )
                .map_err(|problem| {
                    self.turn_failure(ConnectionStage::TurnBindingValidate, problem)
                })?;
                if signed.host_signature.len() != 64 {
                    return Err(self.turn_failure(
                        ConnectionStage::TurnBindingValidate,
                        PeerError::SignalRejected,
                    ));
                }
                if !fresh {
                    self.diagnostics
                        .mark_once(ConnectionStage::TurnBindingExpired);
                    return Ok(false);
                }
                // Reposting an already countersigned binding adds a race
                // with expiry and an unnecessary peer-key HTTP round trip.
                if signed.controller_signature.len() != 64 {
                    let remaining = binding.expires_at_unix_ms.saturating_sub(now_ms()?);
                    if remaining <= 1_000 {
                        return Ok(false);
                    }
                    let full = self
                        .await_bounded(
                            async {
                                self.sdk
                                    .lock()
                                    .await
                                    .prove_turn_peers(&self.identity, &self.permit, &binding)
                                    .await
                                    .map_err(turn_sdk_error)
                            },
                            (if self.mode == PeerPathMode::DirectPreferred {
                                deadline.min(monotonic_ms()? + 3_000.0)
                            } else {
                                deadline
                            })
                            .min(monotonic_ms()? + remaining as f64),
                        )
                        .await;
                    let full = match full {
                        Ok(full) => full,
                        Err(PeerError::RelayUnavailable | PeerError::TimedOut)
                            if self.mode == PeerPathMode::DirectPreferred =>
                        {
                            return Ok(false);
                        }
                        Err(problem) => {
                            return Err(
                                self.turn_failure(ConnectionStage::TurnBindingSign, problem)
                            );
                        }
                    };
                    let full = full.binding.ok_or_else(|| {
                        self.turn_failure(
                            ConnectionStage::TurnBindingValidate,
                            PeerError::SignalRejected,
                        )
                    })?;
                    if full.claims != signed.claims
                        || full.host_signature.len() != 64
                        || full.controller_signature.len() != 64
                    {
                        return Err(self.turn_failure(
                            ConnectionStage::TurnBindingValidate,
                            PeerError::SignalRejected,
                        ));
                    }
                }
                let now = now_ms()?;
                let remaining = binding.expires_at_unix_ms.saturating_sub(now);
                if remaining == 0 {
                    self.diagnostics
                        .mark_once(ConnectionStage::TurnBindingExpired);
                    return Ok(false);
                }
                self.authority.borrow_mut().turn_binding_deadline_ms =
                    Some(monotonic_ms()? + remaining as f64);
                self.authority.borrow_mut().path.turn_bound = true;
                self.diagnostics
                    .mark_once(ConnectionStage::TurnBindingReady);
                return Ok(true);
            }
            Ok(false)
        }

        fn disable_optional_turn(&mut self) -> Result<(), PeerError> {
            let authority = self.authority.borrow();
            if authority.path.selected != Some(SelectedPath::Direct)
                || authority.path.requires_turn()
            {
                return Err(PeerError::SelectedPathRejected);
            }
            drop(authority);
            if self.turn_credentials.is_some() {
                let configuration = rtc_configuration(
                    &self.direct_ice,
                    PeerPathMode::DirectOnly,
                    &self.permit.claims().paths,
                )?;
                self.peer
                    .set_configuration_with_configuration(&configuration)
                    .map_err(|_| PeerError::BrowserOperation)?;
            }
            self.turn_credentials = None;
            self.local_candidate_addresses.clear();
            self.remote_candidate_addresses.clear();
            self.mode = PeerPathMode::DirectOnly;
            let mut authority = self.authority.borrow_mut();
            authority.path.mode = PeerPathMode::DirectOnly;
            authority.path.turn_bound = false;
            authority.turn_deadline_ms = None;
            authority.turn_expires_at_unix_ms = None;
            authority.turn_binding_deadline_ms = None;
            Ok(())
        }

        fn pause_tracks(&self) {
            for receiver in self.peer.get_receivers().iter() {
                if let Ok(receiver) = receiver.dyn_into::<RtcRtpReceiver>() {
                    receiver.track().set_enabled(false);
                }
            }
        }

        fn resume_tracks(&self) -> Result<(), PeerError> {
            self.ensure_live()?;
            if self.proof_complete.get() && self.authority.borrow().path.ready() {
                for receiver in self.peer.get_receivers().iter() {
                    if let Ok(receiver) = receiver.dyn_into::<RtcRtpReceiver>() {
                        receiver.track().set_enabled(true);
                    }
                }
            }
            Ok(())
        }

        pub async fn check_control_status(&self) -> Result<(), PeerError> {
            self.ensure_live()?;
            self.await_bounded(
                async {
                    let view = self
                        .sdk
                        .lock()
                        .await
                        .remote(&self.permit.claims().session_id)
                        .await
                        .map_err(|_| PeerError::SignalRejected)?;
                    if view.status != "approved"
                        || view.connection_generation != self.permit.claims().connection_generation
                        || view.policy_revision != self.permit.claims().policy_revision
                    {
                        return Err(PeerError::InvalidPermit);
                    }
                    Ok(())
                },
                self.operation_deadline(MAX_OPERATION_MS)?,
            )
            .await
        }
        pub async fn media_sample(&self) -> Result<crate::browser_metrics::MediaSample, PeerError> {
            self.ensure_live()?;
            let sample = self
                .await_bounded(
                    async {
                        let value = JsFuture::from(self.peer.get_stats())
                            .await
                            .map_err(|_| PeerError::BrowserOperation)?;
                        let report = value
                            .dyn_into::<RtcStatsReport>()
                            .map_err(|_| PeerError::BrowserOperation)?;
                        Ok(crate::browser_metrics::from_report(
                            &report,
                            monotonic_ms()?,
                        ))
                    },
                    self.operation_deadline(1_000)?,
                )
                .await?;
            if sample.bytes.is_some_and(|bytes| bytes > 0.0) {
                self.diagnostics
                    .mark_once(ConnectionStage::FirstPacketObserved);
            }
            if sample.frames.is_some_and(|frames| frames > 0.0) {
                self.diagnostics
                    .mark_once(ConnectionStage::FirstDecodedFrameObserved);
            }
            Ok(sample)
        }

        async fn publish_description(
            &mut self,
            mut description: WebRtcDescription,
            network_generation: u64,
            deadline: f64,
        ) -> Result<(), PeerError> {
            if self.turn_credentials.is_some() {
                self.local_candidate_addresses =
                    managed_candidate_addresses(self.mode, &description.sdp)?;
            }
            let next = self
                .local_sequence
                .checked_add(1)
                .ok_or(PeerError::SignalRejected)?;
            let claims = self.permit.claims();
            let ice = if self.trickle_enabled() {
                let ice = nestlink_protocol::ice::snapshot(
                    &description.sdp,
                    next,
                    self.peer.ice_gathering_state() == RtcIceGatheringState::Complete,
                )
                .map_err(|_| PeerError::SignalRejected)?;
                description.sdp = nestlink_protocol::ice::without_candidates(&description.sdp);
                Some(ice)
            } else {
                None
            };
            let payload = SignalPayload {
                ice,
                connection_generation: claims.connection_generation,
                lease_sequence: claims.lease_sequence,
                network_generation,
                sequence: next,
                candidates: Vec::<Candidate>::new(),
                description: Some(description),
            };
            payload
                .validate(claims)
                .map_err(|_| PeerError::SignalRejected)?;
            self.await_bounded(
                async {
                    self.sdk
                        .lock()
                        .await
                        .publish_signal(&self.identity, &self.permit, payload.clone())
                        .await
                        .map_err(|_| PeerError::SignalRejected)
                },
                deadline,
            )
            .await?;
            self.local_sequence = next;
            self.local_offer_sequence = next;
            self.local_ice_signal = payload.ice.as_ref().map(|_| payload.clone());
            self.network_generation = network_generation;
            self.diagnostics
                .signal(ConnectionStage::SignalSubmitted, &payload);
            self.diagnostics
                .signal(ConnectionStage::LocalCandidates, &payload);
            if payload
                .ice
                .as_ref()
                .is_some_and(|ice| ice.end_of_candidates)
            {
                self.diagnostics.mark(ConnectionStage::GatherComplete);
            }
            Ok(())
        }

        fn trickle_enabled(&self) -> bool {
            self.permit
                .claims()
                .required_capabilities
                .iter()
                .any(|value| value == nestlink_protocol::ice::TRICKLE_CAPABILITY)
        }

        async fn publish_local_ice(&mut self, deadline: f64) -> Result<(), PeerError> {
            let Some(mut signal) = self.local_ice_signal.clone() else {
                return Ok(());
            };
            self.ensure_live()?;
            let local = self
                .peer
                .local_description()
                .ok_or(PeerError::BrowserOperation)?;
            let snapshot = nestlink_protocol::ice::snapshot(
                &local.sdp(),
                signal.description_sequence(),
                self.peer.ice_gathering_state() == RtcIceGatheringState::Complete,
            )
            .map_err(|_| PeerError::SignalRejected)?;
            if signal.ice.as_ref() == Some(&snapshot) {
                return Ok(());
            }
            self.local_sequence = self
                .local_sequence
                .checked_add(1)
                .ok_or(PeerError::SignalRejected)?;
            signal.sequence = self.local_sequence;
            signal.lease_sequence = self.permit.claims().lease_sequence;
            signal.ice = Some(snapshot);
            self.await_bounded(
                async {
                    self.sdk
                        .lock()
                        .await
                        .publish_signal(&self.identity, &self.permit, signal.clone())
                        .await
                        .map_err(|_| PeerError::SignalRejected)
                },
                deadline,
            )
            .await?;
            self.diagnostics
                .signal(ConnectionStage::SignalSubmitted, &signal);
            self.diagnostics
                .signal(ConnectionStage::LocalCandidates, &signal);
            if signal.ice.as_ref().is_some_and(|ice| ice.end_of_candidates) {
                self.diagnostics.mark(ConnectionStage::GatherComplete);
            }
            self.local_ice_signal = Some(signal);
            Ok(())
        }

        async fn apply_remote_ice(&mut self, signal: &SignalPayload) -> Result<(), PeerError> {
            let Some(ice) = &signal.ice else {
                return Ok(());
            };
            if ice.description_sequence != self.remote_answer_sequence {
                return Err(PeerError::SignalRejected);
            }
            signal
                .validate(self.permit.claims())
                .map_err(|_| PeerError::SignalRejected)?;
            for candidate in self
                .remote_ice
                .apply(ice)
                .map_err(|_| PeerError::SignalRejected)?
            {
                self.ensure_live()?;
                let init = RtcIceCandidateInit::new(&candidate.candidate);
                init.set_sdp_mid(candidate.sdp_mid.as_deref());
                init.set_sdp_m_line_index(Some(candidate.sdp_m_line_index));
                js_sys::Reflect::set(
                    init.as_ref(),
                    &JsValue::from_str("usernameFragment"),
                    &JsValue::from_str(&candidate.username_fragment),
                )
                .map_err(|_| PeerError::BrowserOperation)?;
                JsFuture::from(
                    self.peer
                        .add_ice_candidate_with_opt_rtc_ice_candidate_init(Some(&init)),
                )
                .await
                .map_err(|_| PeerError::BrowserOperation)?;
            }
            if ice.end_of_candidates {
                JsFuture::from(
                    self.peer
                        .add_ice_candidate_with_opt_rtc_ice_candidate_init(None),
                )
                .await
                .map_err(|_| PeerError::BrowserOperation)?;
            }
            self.diagnostics
                .signal(ConnectionStage::RemoteCandidates, signal);
            Ok(())
        }

        async fn wait_for_ice_gathering(&mut self, deadline: f64) -> Result<(), PeerError> {
            let gather_deadline = deadline.min(monotonic_ms()? + f64::from(ICE_GATHER_TIMEOUT_MS));
            loop {
                self.ensure_live()?;
                // ICE gathering can overlap a host renewal. Consume it on
                // every bounded poll so a network restart cannot hold the
                // previous permit until its expiry edge.
                self.renew_from_host_before(gather_deadline).await?;
                self.maintain_turn_allocation_before(gather_deadline)
                    .await?;
                if self.peer.ice_gathering_state() == RtcIceGatheringState::Complete {
                    self.diagnostics.mark(ConnectionStage::GatherComplete);
                    return Ok(());
                }
                self.wait_tick(gather_deadline).await?;
            }
        }

        async fn wait_tick(&self, deadline: f64) -> Result<(), PeerError> {
            let now = monotonic_ms()?;
            let remaining = deadline - now;
            if remaining <= 1.0 {
                return Err(PeerError::TimedOut);
            }
            // Wake before permit expiry so a caller with a renewable operation
            // budget can consume a pending host signature while its old permit
            // is still live. Never let the poll timer cross that authority edge.
            let permit_remaining = self.authority.borrow().permit_deadline_ms - now;
            let permit_wait = permit_remaining - 1.0;
            if permit_wait <= 0.0 {
                return Err(PeerError::Expired);
            }
            let sleep_ms = remaining
                .min(permit_wait)
                .min(f64::from(POLL_INTERVAL_MS))
                .floor() as u32;
            self.await_bounded(
                async move {
                    TimeoutFuture::new(sleep_ms).await;
                    Ok(())
                },
                deadline,
            )
            .await
        }

        async fn await_bounded<T, F>(&self, future: F, deadline: f64) -> Result<T, PeerError>
        where
            F: Future<Output = Result<T, PeerError>>,
        {
            bounded_live(
                future,
                deadline,
                &self.peer,
                &self.cancelled,
                &self.authority,
            )
            .await
        }

        fn operation_deadline(&self, timeout_ms: u32) -> Result<f64, PeerError> {
            self.ensure_live()?;
            let now = monotonic_ms()?;
            let timeout = timeout_ms.clamp(1, MAX_OPERATION_MS) as f64;
            let authority = self.authority.borrow();
            Ok((now + timeout)
                .min(authority.endpoint_deadline_ms)
                .min(authority.permit_deadline_ms)
                .min(if authority.path.requires_turn() {
                    authority.turn_deadline_ms.unwrap_or(f64::INFINITY)
                } else {
                    f64::INFINITY
                }))
        }

        fn renewable_operation_deadline(&self, timeout_ms: u32) -> Result<f64, PeerError> {
            self.ensure_live()?;
            let now = monotonic_ms()?;
            let timeout = timeout_ms.clamp(1, MAX_OPERATION_MS) as f64;
            // Permit and TURN deadlines may move forward only after their
            // separately authenticated renewal succeeds. Keep the user-visible
            // operation budget fixed while allowing those renewals to complete.
            Ok((now + timeout).min(self.authority.borrow().endpoint_deadline_ms))
        }

        fn ensure_live(&self) -> Result<(), PeerError> {
            check_authority(&self.peer, &self.cancelled, &self.authority)
        }
    }

    impl Drop for BrowserPeer {
        fn drop(&mut self) {
            self.diagnostics.mark_once(ConnectionStage::Stopped);
            self.display_permit.borrow_mut().take();
            self.display_deadline.set(None);
            self.data.close();
            close_peer(&self.peer, &self.cancelled);
            if let Some(window) = web_sys::window() {
                window.clear_interval_with_handle(self.expiry_timer);
            }
            self.control_channel.set_onmessage(None);
            self.control_channel.close();
            self.peer.close();
            let _ = &self.expiry_handler;
            let _ = &self.path_monitor;
            let _ = &self.control_handler;
        }
    }

    fn now_ms() -> Result<u64, PeerError> {
        let now = Date::now();
        if !now.is_finite() || now < 0.0 {
            return Err(PeerError::BrowserUnavailable);
        }
        Ok(now as u64)
    }

    fn monotonic_ms() -> Result<f64, PeerError> {
        let now = web_sys::window()
            .and_then(|window| window.performance())
            .ok_or(PeerError::BrowserUnavailable)?
            .now();
        if !now.is_finite() || now < 0.0 {
            return Err(PeerError::BrowserUnavailable);
        }
        Ok(now)
    }

    async fn bounded_live<T, F>(
        future: F,
        deadline: f64,
        peer: &RtcPeerConnection,
        cancelled: &Cell<bool>,
        authority: &RefCell<PeerAuthority>,
    ) -> Result<T, PeerError>
    where
        F: Future<Output = Result<T, PeerError>>,
    {
        let mut operation = Box::pin(future);
        loop {
            check_authority(peer, cancelled, authority)?;
            let remaining = deadline - monotonic_ms()?;
            if remaining <= 0.0 {
                return Err(PeerError::TimedOut);
            }
            let wait_ms = remaining.min(f64::from(POLL_INTERVAL_MS)).max(1.0) as u32;
            match select(operation, Box::pin(TimeoutFuture::new(wait_ms))).await {
                futures_util::future::Either::Left((result, _)) => {
                    check_authority(peer, cancelled, authority)?;
                    if monotonic_ms()? >= deadline {
                        return Err(PeerError::TimedOut);
                    }
                    return result;
                }
                futures_util::future::Either::Right((_, pending)) => operation = pending,
            }
        }
    }

    fn restrict_local_description(
        description: &RtcSessionDescriptionInit,
        claims: &PermitClaims,
    ) -> Result<(), PeerError> {
        let sdp = description.get_sdp().ok_or(PeerError::BrowserOperation)?;
        let restricted = restrict_media_sdp(&sdp, &claims.permissions)
            .map_err(|_| PeerError::CodecUnavailable)?;
        description.set_sdp(&restricted);
        Ok(())
    }

    fn managed_ice_configuration(
        credentials: &TurnCredentials,
    ) -> Result<TrustedIceConfiguration, PeerError> {
        let claims = credentials.claims();
        TrustedIceConfiguration::from_trusted_deployment_config(vec![TrustedIceServer::turn(
            claims.endpoints.clone(),
            claims.username.clone(),
            claims.password.clone(),
        )])
    }

    fn renewal_handler(
        peer: &RtcPeerConnection,
        channel: &RtcDataChannel,
        cancelled: Rc<Cell<bool>>,
        authority: Rc<RefCell<PeerAuthority>>,
        state: ControlReceiveState,
    ) -> Closure<dyn FnMut(MessageEvent)> {
        let peer = peer.clone();
        let channel = channel.clone();
        let ControlReceiveState {
            pending,
            proofs,
            proof_complete,
            acceptance_expected,
            accepted_queued,
            pending_catalog,
            input: input_state,
            displays,
            display_deadline,
            display_permit,
        } = state;
        let mut previous: Option<WebRtcControl> = None;
        Closure::wrap(Box::new(move |event: MessageEvent| {
            if check_authority(&peer, &cancelled, &authority).is_err() {
                return;
            }
            let data = event.data();
            let (bytes, binary) = if let Some(text) = data.as_string() {
                if text.len() > MAX_WEBRTC_CONTROL_BYTES {
                    close_peer(&peer, &cancelled);
                    return;
                }
                (text.into_bytes(), false)
            } else if let Ok(buffer) = data.dyn_into::<ArrayBuffer>() {
                if buffer.byte_length() as usize > MAX_WEBRTC_CONTROL_BYTES {
                    close_peer(&peer, &cancelled);
                    return;
                }
                (Uint8Array::new(&buffer).to_vec(), true)
            } else {
                close_peer(&peer, &cancelled);
                return;
            };
            if bytes.starts_with(b"NLDB") {
                let receive = || -> Result<(), PeerError> {
                    if !binary || !authority.borrow().path.ready() {
                        return Err(PeerError::SignalRejected);
                    }
                    let control = {
                        let authority = authority.borrow();
                        let pinned = display_permit.borrow();
                        DisplayPermitWindow::new(
                            Some(&authority.permit),
                            pinned.as_ref(),
                            display_deadline.get(),
                            authority.last_unix_ms,
                            authority.last_monotonic_ms,
                        )
                        .decode_display(&bytes)?
                    };
                    if !proof_complete.get() {
                        if !accepted_queued.get() {
                            return Err(PeerError::SignalRejected);
                        }
                        pending_catalog.borrow_mut().push(control, bytes.len())?;
                        return Ok(());
                    }
                    apply_display_control(
                        &channel,
                        &authority,
                        &input_state,
                        &displays,
                        &display_deadline,
                        &display_permit,
                        control,
                    )
                };
                if receive().is_err() {
                    close_peer(&peer, &cancelled);
                }
                return;
            }
            let Ok(message) = serde_json::from_slice::<WebRtcControl>(&bytes) else {
                close_peer(&peer, &cancelled);
                return;
            };
            if matches!(message, WebRtcControl::HostRenewalSignature { .. })
                && previous.as_ref() == Some(&message)
            {
                return;
            }
            let validation = {
                let authority = authority.borrow();
                let pinned = display_permit.borrow();
                DisplayPermitWindow::new(
                    Some(&authority.permit),
                    pinned.as_ref(),
                    display_deadline.get(),
                    authority.last_unix_ms,
                    authority.last_monotonic_ms,
                )
                .validate_json(&message)
            };
            if validation.is_err() {
                close_peer(&peer, &cancelled);
                return;
            }
            if matches!(message, WebRtcControl::HostRenewalSignature { .. }) {
                previous = Some(message.clone());
                *pending.borrow_mut() = Some(message);
                return;
            }
            match message {
                WebRtcControl::HostInputLayout {
                    left,
                    top,
                    width,
                    height,
                    input_epoch,
                    layout_epoch,
                    ..
                } => {
                    if !proof_complete.get()
                        || !authority
                            .borrow()
                            .permit
                            .claims()
                            .permissions
                            .contains(&(Permission::Input as i32))
                    {
                        close_peer(&peer, &cancelled);
                        return;
                    }
                    let layout = PeerInputLayout {
                        left,
                        top,
                        width,
                        height,
                        input_epoch,
                        layout_epoch,
                    };
                    let mut state = input_state.borrow_mut();
                    if !state.suspended
                        || state.pending_layout.is_some()
                        || displays
                            .borrow()
                            .validate_layout((left, top, width, height), input_epoch, layout_epoch)
                            .is_err()
                    {
                        close_peer(&peer, &cancelled);
                        return;
                    }
                    state.pending_layout = Some(layout);
                }
                message @ (WebRtcControl::EndpointProof { .. }
                | WebRtcControl::EndpointProofAccepted { .. })
                    if !proof_complete.get() =>
                {
                    if matches!(&message, WebRtcControl::EndpointProofAccepted { .. }) {
                        if !acceptance_expected.get() || accepted_queued.replace(true) {
                            close_peer(&peer, &cancelled);
                            return;
                        }
                    } else if accepted_queued.get() {
                        close_peer(&peer, &cancelled);
                        return;
                    }
                    let mut queue = proofs.borrow_mut();
                    if queue.len() >= 4 {
                        close_peer(&peer, &cancelled);
                        return;
                    }
                    queue.push_back(message);
                }
                _ => close_peer(&peer, &cancelled),
            }
        }) as Box<dyn FnMut(MessageEvent)>)
    }

    fn pending_display_permit(
        authority: &RefCell<PeerAuthority>,
        pending: &RefCell<Option<VerifiedPermit>>,
        deadline: &Cell<Option<f64>>,
    ) -> Result<VerifiedPermit, PeerError> {
        authority.borrow_mut().check()?;
        let permit = pending.borrow().clone().ok_or(PeerError::SignalRejected)?;
        let authority = authority.borrow();
        DisplayPermitWindow::new(
            Some(&authority.permit),
            Some(&permit),
            deadline.get(),
            authority.last_unix_ms,
            authority.last_monotonic_ms,
        )
        .transaction()?;
        Ok(permit)
    }

    fn apply_display_control(
        channel: &RtcDataChannel,
        authority: &RefCell<PeerAuthority>,
        input_state: &RefCell<InputSendState>,
        displays: &RefCell<DisplayClientState>,
        display_deadline: &Cell<Option<f64>>,
        display_permit: &RefCell<Option<VerifiedPermit>>,
        control: WebRtcDisplayControl,
    ) -> Result<(), PeerError> {
        let permit = if matches!(control.message, DisplayEnvelope::Selected(_)) {
            pending_display_permit(authority, display_permit, display_deadline)?
        } else {
            authority.borrow().permit.clone()
        };
        control
            .validate(permit.claims())
            .map_err(|_| PeerError::SignalRejected)?;
        match control.message {
            DisplayEnvelope::Selected(selection) => {
                displays.borrow().validate_selection(&selection)?;
                let mut input = input_state.borrow_mut();
                let has_input = permit
                    .claims()
                    .permissions
                    .contains(&(Permission::Input as i32));
                if has_input {
                    let layout = input.pending_layout.ok_or(PeerError::SignalRejected)?;
                    if layout.input_epoch != selection.input_epoch
                        || layout.layout_epoch != selection.layout_epoch
                    {
                        return Err(PeerError::SignalRejected);
                    }
                } else if input.pending_layout.is_some() {
                    return Err(PeerError::SignalRejected);
                }
                send_display_control(
                    channel,
                    &DisplayEnvelope::SelectionAck(selection.clone()),
                    permit.claims(),
                )?;
                displays.borrow_mut().commit_selection(selection)?;
                input.layout = input.pending_layout.take();
                input.sequence = 0;
                input.suspended = false;
                display_deadline.set(None);
                display_permit.borrow_mut().take();
            }
            catalog @ (DisplayEnvelope::CatalogBegin { .. }
            | DisplayEnvelope::CatalogEntry { .. }
            | DisplayEnvelope::CatalogCommit(_)) => {
                if let Some(reply) = displays.borrow_mut().receive_catalog(catalog)? {
                    send_display_control(channel, &reply, authority.borrow().permit.claims())?;
                }
            }
            _ => return Err(PeerError::SignalRejected),
        }
        Ok(())
    }

    fn send_display_control(
        channel: &RtcDataChannel,
        envelope: &DisplayEnvelope,
        claims: &PermitClaims,
    ) -> Result<(), PeerError> {
        let bytes = WebRtcDisplayControl {
            schema_version: claims.schema_version,
            session_id: claims.session_id.clone(),
            connection_generation: claims.connection_generation,
            lease_sequence: claims.lease_sequence,
            message: envelope.clone(),
        }
        .encode_validated(claims)
        .map_err(|_| PeerError::SignalRejected)?;
        if channel.ready_state() != web_sys::RtcDataChannelState::Open
            || channel.buffered_amount() > 1_048_576
        {
            return Err(PeerError::BrowserOperation);
        }
        channel
            .send_with_u8_array(&bytes)
            .map_err(|_| PeerError::BrowserOperation)
    }

    fn rtc_configuration(
        trusted: &TrustedIceConfiguration,
        mode: PeerPathMode,
        allowed_paths: &[i32],
    ) -> Result<RtcConfiguration, PeerError> {
        if mode == PeerPathMode::RelayOnly && !trusted.has_turn() {
            return Err(PeerError::RelayUnavailable);
        }
        let allow_direct = allowed_paths.contains(&(Path::Direct as i32));
        let allow_relay = allowed_paths.contains(&(Path::Relay as i32));
        let servers = Array::new();
        for server in &trusted.servers {
            let urls: Vec<_> = server
                .urls
                .iter()
                .filter(|url| {
                    let is_turn = url.starts_with("turn:") || url.starts_with("turns:");
                    match mode {
                        PeerPathMode::DirectOnly => !is_turn && allow_direct,
                        PeerPathMode::RelayOnly => is_turn && allow_relay,
                        PeerPathMode::DirectPreferred => {
                            if is_turn {
                                allow_relay
                            } else {
                                allow_direct
                            }
                        }
                    }
                })
                .collect();
            if urls.is_empty() {
                continue;
            }
            let js_urls = Array::new();
            for url in urls {
                js_urls.push(&JsValue::from_str(url));
            }
            let ice_server = RtcIceServer::new();
            ice_server.set_urls(&js_urls.into());
            if server.has_turn() {
                ice_server.set_username(
                    server
                        .username
                        .as_deref()
                        .ok_or(PeerError::InvalidIceConfiguration)?,
                );
                ice_server.set_credential(
                    server
                        .credential
                        .as_deref()
                        .ok_or(PeerError::InvalidIceConfiguration)?,
                );
            }
            servers.push(&ice_server.into());
        }
        if mode == PeerPathMode::RelayOnly && servers.length() == 0 {
            return Err(PeerError::RelayUnavailable);
        }
        let configuration = RtcConfiguration::new();
        configuration.set_ice_servers(&servers.into());
        configuration.set_ice_transport_policy(match mode {
            PeerPathMode::RelayOnly => RtcIceTransportPolicy::Relay,
            PeerPathMode::DirectOnly | PeerPathMode::DirectPreferred => RtcIceTransportPolicy::All,
        });
        Ok(configuration)
    }

    fn rtc_description(
        description: &WebRtcDescription,
        claims: &PermitClaims,
    ) -> Result<RtcSessionDescriptionInit, PeerError> {
        description
            .validate(claims)
            .map_err(|_| PeerError::SignalRejected)?;
        validate_media_sdp(&description.sdp, &claims.permissions)
            .map_err(|_| PeerError::CodecUnavailable)?;
        let kind = match description.kind.as_str() {
            "offer" => RtcSdpType::Offer,
            "answer" => RtcSdpType::Answer,
            _ => return Err(PeerError::AnswerRequired),
        };
        let result = RtcSessionDescriptionInit::new(kind);
        result.set_sdp(&description.sdp);
        Ok(result)
    }

    fn web_description(
        kind: &str,
        sdp: String,
        claims: &PermitClaims,
    ) -> Result<WebRtcDescription, PeerError> {
        let fingerprint = sdp
            .lines()
            .filter_map(|line| line.strip_prefix("a=fingerprint:sha-256 "))
            .map(|value| {
                value
                    .split(':')
                    .map(|byte| u8::from_str_radix(byte, 16))
                    .collect::<Result<Vec<_>, _>>()
            })
            .next()
            .ok_or(PeerError::SignalRejected)?
            .map_err(|_| PeerError::SignalRejected)?;
        let description = WebRtcDescription {
            kind: kind.into(),
            sdp,
            dtls_sha256: fingerprint,
            in_reply_to_sequence: None,
        };
        description
            .validate(claims)
            .map_err(|_| PeerError::SignalRejected)?;
        validate_media_sdp(&description.sdp, &claims.permissions)
            .map_err(|_| PeerError::CodecUnavailable)?;
        Ok(description)
    }

    async fn wait_for_selected_path(
        peer: &RtcPeerConnection,
        cancelled: &Cell<bool>,
        authority: &RefCell<PeerAuthority>,
        mode: PeerPathMode,
        paths: &[i32],
        deadline: f64,
    ) -> Result<SelectedPath, PeerError> {
        bounded_live(
            async {
                loop {
                    match peer.connection_state() {
                        RtcPeerConnectionState::Connected => {
                            match selected_path_from_peer(peer).await {
                                // During an ICE restart the aggregate peer can
                                // stay connected while its new pair is still
                                // in progress. Keep the original operation and
                                // authorization deadlines while waiting for it.
                                Err(PeerError::NoSelectedPath) => {}
                                Err(problem) => return Err(problem),
                                Ok(selected) => {
                                    match verify_live_path(authority, selected) {
                                        // TURN permissions can become active before the
                                        // controller's binding response is delivered.
                                        Err(PeerError::NoSelectedPath) => {}
                                        Err(problem) => return Err(problem),
                                        Ok(()) => {
                                            return verify_selected_paths(mode, paths, &[selected]);
                                        }
                                    }
                                }
                            }
                        }
                        RtcPeerConnectionState::Failed | RtcPeerConnectionState::Closed => {
                            return Err(PeerError::SelectedPathRejected);
                        }
                        _ => {}
                    }
                    TimeoutFuture::new(POLL_INTERVAL_MS).await;
                }
            },
            deadline,
            peer,
            cancelled,
            authority,
        )
        .await
    }

    async fn selected_path_from_peer(peer: &RtcPeerConnection) -> Result<SelectedPath, PeerError> {
        let value = JsFuture::from(peer.get_stats())
            .await
            .map_err(|_| PeerError::BrowserOperation)?;
        let report = value
            .dyn_into::<RtcStatsReport>()
            .map_err(|_| PeerError::BrowserOperation)?;
        selected_path_from_report(&report)
    }

    fn selected_path_from_report(report: &RtcStatsReport) -> Result<SelectedPath, PeerError> {
        let mut selected = Vec::new();
        let iterator: Iterator = report.values();
        loop {
            let entry = iterator.next().map_err(|_| PeerError::BrowserOperation)?;
            if entry.done() {
                break;
            }
            let value = entry.value();
            let statistic: RtcStats = value.unchecked_into();
            if statistic.get_type() != Some(RtcStatsType::CandidatePair) {
                continue;
            }
            let pair: RtcIceCandidatePairStats = statistic.unchecked_into();
            let selected_pair = pair.get_selected() == Some(true)
                || (pair.get_selected().is_none()
                    && pair.get_nominated() == Some(true)
                    && pair.get_state() == Some(RtcStatsIceCandidatePairState::Succeeded));
            if !selected_pair {
                continue;
            }
            let local_id = pair
                .get_local_candidate_id()
                .ok_or(PeerError::NoSelectedPath)?;
            let remote_id = pair
                .get_remote_candidate_id()
                .ok_or(PeerError::NoSelectedPath)?;
            let local: RtcIceCandidateStats = report
                .get(&local_id)
                .ok_or(PeerError::NoSelectedPath)?
                .unchecked_into();
            let remote: RtcIceCandidateStats = report
                .get(&remote_id)
                .ok_or(PeerError::NoSelectedPath)?
                .unchecked_into();
            let local_relay = local.get_candidate_type() == Some(RtcStatsIceCandidateType::Relayed);
            let remote_relay =
                remote.get_candidate_type() == Some(RtcStatsIceCandidateType::Relayed);
            selected.push(path_from_candidate_types(local_relay, remote_relay));
        }
        verify_multiplexed_selected_paths(&selected)
    }

    fn ice_checks_from_report(
        report: &RtcStatsReport,
    ) -> Result<nestlink_protocol::diagnostics::IceCheckSnapshot, PeerError> {
        let mut snapshot = nestlink_protocol::diagnostics::IceCheckSnapshot::default();
        let iterator: Iterator = report.values();
        for _ in 0..4096 {
            let entry = iterator.next().map_err(|_| PeerError::BrowserOperation)?;
            if entry.done() {
                return Ok(snapshot);
            }
            let statistic: RtcStats = entry.value().unchecked_into();
            if statistic.get_type() != Some(RtcStatsType::CandidatePair) {
                continue;
            }
            let pair: RtcIceCandidatePairStats = statistic.unchecked_into();
            let kind = |id: Option<String>| {
                id.and_then(|id| report.get(&id))
                    .map(|value| value.unchecked_into::<RtcIceCandidateStats>())
                    .and_then(|candidate| candidate.get_candidate_type())
            };
            let local = kind(pair.get_local_candidate_id());
            let remote = kind(pair.get_remote_candidate_id());
            let path = if local == Some(RtcStatsIceCandidateType::Relayed)
                || remote == Some(RtcStatsIceCandidateType::Relayed)
            {
                &mut snapshot.relay
            } else if local.is_some() && remote.is_some() {
                &mut snapshot.direct
            } else {
                &mut snapshot.unknown
            };
            path.pairs += 1;
            path.nominated += u64::from(pair.get_nominated() == Some(true));
            match pair.get_state() {
                Some(RtcStatsIceCandidatePairState::Inprogress) => path.in_progress += 1,
                Some(RtcStatsIceCandidatePairState::Succeeded) => path.succeeded += 1,
                Some(RtcStatsIceCandidatePairState::Failed) => path.failed += 1,
                _ => {}
            }
            let pair_count = path.pairs;
            let add = |field: &str, total: &mut Option<u64>| {
                let value = js_sys::Reflect::get(pair.as_ref(), &field.into())
                    .ok()
                    .and_then(|value| value.as_f64())
                    .filter(|n| {
                        n.is_finite()
                            && *n >= 0.0
                            && n.fract() == 0.0
                            && *n <= 9_007_199_254_740_991.0
                    })
                    .map(|value| value as u64);
                *total = if pair_count == 1 {
                    value
                } else {
                    total
                        .zip(value)
                        .map(|(old, value)| old.saturating_add(value))
                };
            };
            add("requestsSent", &mut path.requests_sent);
            add("requestsReceived", &mut path.requests_received);
            add("responsesSent", &mut path.responses_sent);
            add("responsesReceived", &mut path.responses_received);
        }
        Err(PeerError::BrowserOperation)
    }

    fn verify_multiplexed_selected_paths(
        paths: &[SelectedPath],
    ) -> Result<SelectedPath, PeerError> {
        if paths.is_empty() {
            return Err(PeerError::NoSelectedPath);
        }
        let has_direct = paths.contains(&SelectedPath::Direct);
        let has_relay = paths.contains(&SelectedPath::Relay);
        match (has_direct, has_relay) {
            (true, true) => Ok(SelectedPath::Mixed),
            (true, false) => Ok(SelectedPath::Direct),
            (false, true) => Ok(SelectedPath::Relay),
            (false, false) => Err(PeerError::NoSelectedPath),
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use crate::browser_displays::PeerDisplaySnapshot;
#[cfg(target_arch = "wasm32")]
pub use wasm::{BrowserPeer, PeerCancellation, PeerInputLayout, PeerInputSender};
