//! Explicit local dialing consent. A server or remote peer cannot approve LAN
//! destinations by publishing candidates or deployment discovery endpoints.
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[cfg(not(target_arch = "wasm32"))]
mod file;
#[cfg(not(target_arch = "wasm32"))]
pub use file::NativeNetworkFileStore;
#[cfg(not(target_arch = "wasm32"))]
pub use nestlink_platform_security::MetadataCommit as NativeNetworkCommit;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeNetworkSettings {
    #[serde(default)]
    pub media_route: MediaRouteMode,
    #[serde(default)]
    pub media_interface_index: Option<u32>,
    pub use_deployment_stun: bool,
    pub private_network_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaRouteMode {
    System,
    Physical,
    Interface,
}

impl Default for MediaRouteMode {
    fn default() -> Self {
        if cfg!(windows) {
            Self::Physical
        } else {
            Self::System
        }
    }
}

impl Default for NativeNetworkSettings {
    fn default() -> Self {
        Self {
            media_route: MediaRouteMode::default(),
            media_interface_index: None,
            use_deployment_stun: true,
            private_network_prefixes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeNetworkError {
    #[error("local network settings are invalid")]
    Invalid,
    #[error("stop current sessions before changing local network settings")]
    Busy,
    #[error("the displayed configuration is no longer current")]
    StaleGeneration,
    #[error("native networking is unavailable")]
    Unavailable,
    #[error("the application is stopped")]
    Stopped,
    #[error("local network settings could not be saved")]
    Persistence,
}

impl NativeNetworkSettings {
    /// Only canonical RFC1918/ULA subnets can be approved here. Public
    /// destinations need no exception; metadata, loopback, mapped IPv6 and
    /// link-local destinations remain forbidden by the SDK AddressPolicy.
    pub fn validate(&self) -> Result<(), NativeNetworkError> {
        if !cfg!(windows) && self.media_route != MediaRouteMode::System {
            return Err(NativeNetworkError::Unavailable);
        }
        if (self.media_route == MediaRouteMode::Interface) != self.media_interface_index.is_some()
            || self.media_interface_index == Some(0)
        {
            return Err(NativeNetworkError::Invalid);
        }
        if self.private_network_prefixes.len() > 32 {
            return Err(NativeNetworkError::Invalid);
        }
        let mut seen = std::collections::HashSet::new();
        for value in &self.private_network_prefixes {
            if value.len() > 48 || !seen.insert(value) {
                return Err(NativeNetworkError::Invalid);
            }
            let (ip, prefix) = value.split_once('/').ok_or(NativeNetworkError::Invalid)?;
            let address: IpAddr = ip.parse().map_err(|_| NativeNetworkError::Invalid)?;
            let prefix: u8 = prefix.parse().map_err(|_| NativeNetworkError::Invalid)?;
            if value != &format!("{address}/{prefix}") {
                return Err(NativeNetworkError::Invalid);
            }
            let valid = match address {
                IpAddr::V4(ip) if prefix <= 32 && ip.is_private() => {
                    let bits = ip.to_bits();
                    let minimum = match ip.octets() {
                        [10, ..] => 8,
                        [172, ..] => 12,
                        [192, 168, ..] => 16,
                        _ => return Err(NativeNetworkError::Invalid),
                    };
                    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
                    prefix >= minimum && bits & mask == bits
                }
                IpAddr::V6(ip) if prefix <= 128 && ip.is_unique_local() => {
                    let bits = ip.to_bits();
                    let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
                    prefix >= 7 && bits & mask == bits
                }
                _ => false,
            };
            if !valid {
                return Err(NativeNetworkError::Invalid);
            }
        }
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn apply_route_policy(&self) -> Result<(), NativeNetworkError> {
        use nestlink_platform_network::path::{RoutePolicy, set_default_policy};
        let policy = match self.media_route {
            MediaRouteMode::System => RoutePolicy::System,
            MediaRouteMode::Physical => RoutePolicy::PreferPhysical,
            MediaRouteMode::Interface => RoutePolicy::Interface(
                self.media_interface_index
                    .ok_or(NativeNetworkError::Invalid)?,
            ),
        };
        if !cfg!(windows) && policy != RoutePolicy::System {
            return Err(NativeNetworkError::Unavailable);
        }
        set_default_policy(policy).map_err(|_| NativeNetworkError::Unavailable)
    }
}

/// The actor saves a validated, idle-only change before publishing it. The
/// platform supplies this store from a checked local directory, never a
/// remote management response. An error guarantees no replacement committed;
/// a visible commit must be published even if directory durability is unknown.
#[cfg(not(target_arch = "wasm32"))]
pub trait NativeNetworkSettingsStore: Send + Sync {
    fn load(&self) -> Result<NativeNetworkSettings, NativeNetworkError>;
    fn save(
        &self,
        settings: &NativeNetworkSettings,
    ) -> Result<NativeNetworkCommit, NativeNetworkError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_does_not_approve_any_private_destination() {
        let settings = NativeNetworkSettings::default();
        assert_eq!(
            settings.media_route,
            if cfg!(windows) {
                MediaRouteMode::Physical
            } else {
                MediaRouteMode::System
            }
        );
        assert!(settings.use_deployment_stun);
        assert!(settings.private_network_prefixes.is_empty());
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn legacy_settings_get_platform_default_but_explicit_route_is_preserved()
    -> Result<(), serde_json::Error> {
        let settings: NativeNetworkSettings =
            serde_json::from_str(r#"{"use_deployment_stun":true,"private_network_prefixes":[]}"#)?;
        assert_eq!(settings, NativeNetworkSettings::default());
        let explicit: NativeNetworkSettings = serde_json::from_str(
            r#"{"media_route":"system","use_deployment_stun":true,"private_network_prefixes":[]}"#,
        )?;
        assert_eq!(explicit.media_route, MediaRouteMode::System);
        assert!(explicit.private_network_prefixes.is_empty());
        Ok(())
    }

    #[test]
    fn consent_requires_canonical_private_subnets_and_bounded_input() {
        for prefix in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.12.0/24",
            "fc00::/7",
            "fd12:3456::/32",
        ] {
            let settings = NativeNetworkSettings {
                private_network_prefixes: vec![prefix.into()],
                ..Default::default()
            };
            assert!(settings.validate().is_ok(), "{prefix}");
        }
        for prefix in [
            "0.0.0.0/0",
            "10.0.0.0/0",
            "172.0.0.0/8",
            "192.0.0.0/8",
            "192.168.1.1/24",
            "10.0.0.0/33",
            "10.0.0.0/08",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "100.64.0.0/10",
            "8.8.8.0/24",
            "::/0",
            "::ffff:10.0.0.0/104",
            "fe80::/10",
            "fd00::/6",
            "fd12::1/64",
            "fd00::/129",
            "10.0.0.0/8 ",
            "10.0.0.0",
        ] {
            let settings = NativeNetworkSettings {
                private_network_prefixes: vec![prefix.into()],
                ..Default::default()
            };
            assert_eq!(
                settings.validate(),
                Err(NativeNetworkError::Invalid),
                "{prefix}"
            );
        }
        let duplicate = NativeNetworkSettings {
            private_network_prefixes: vec!["10.0.0.0/8".into(); 2],
            ..Default::default()
        };
        assert!(duplicate.validate().is_err());
        let oversized = NativeNetworkSettings {
            private_network_prefixes: vec!["10.0.0.0/8".into(); 33],
            ..Default::default()
        };
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn settings_json_cannot_supply_stun_servers_or_remote_authority() {
        assert!(serde_json::from_str::<NativeNetworkSettings>(
            r#"{"use_deployment_stun":true,"private_network_prefixes":[],"stun_servers":["127.0.0.1:80"]}"#
        ).is_err());
    }
}
