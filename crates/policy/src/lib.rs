//! Explicit set intersection; enum ordering never determines permission.
use nestlink_protocol::{ContractError, ErrorCode, Path};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerForwarding {
    #[default]
    Deny,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerPathMode {
    #[default]
    DirectOnly,
    DirectPreferred,
    RelayOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicIngress {
    #[default]
    Disabled,
    Enabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub server_forwarding: ServerForwarding,
    pub peer_path_mode: PeerPathMode,
    pub public_ingress: PublicIngress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathSet(u8);

impl PathSet {
    pub const DIRECT: Self = Self(1);
    pub const RELAY: Self = Self(2);
    pub const BOTH: Self = Self(3);
    pub const EMPTY: Self = Self(0);

    pub fn contains(self, path: Path) -> bool {
        match path {
            Path::Direct => self.0 & 1 != 0,
            Path::Relay => self.0 & 2 != 0,
            _ => false,
        }
    }
    pub fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
    pub fn is_empty(self) -> bool {
        self == Self::EMPTY
    }
    pub fn to_wire(self) -> Vec<i32> {
        [Path::Direct, Path::Relay]
            .into_iter()
            .filter(|p| self.contains(*p))
            .map(|p| p as i32)
            .collect()
    }
    pub fn from_wire(paths: &[i32]) -> Result<Self, ContractError> {
        let mut result = Self::EMPTY;
        for value in paths {
            let path = Path::try_from(*value)
                .map_err(|_| ContractError::new(ErrorCode::InvalidMessage, "unknown path"))?;
            let bit = match path {
                Path::Direct => Self::DIRECT,
                Path::Relay => Self::RELAY,
                _ => {
                    return Err(ContractError::new(
                        ErrorCode::InvalidMessage,
                        "unspecified path",
                    ));
                }
            };
            if result.contains(path) {
                return Err(ContractError::new(
                    ErrorCode::InvalidMessage,
                    "duplicate path",
                ));
            }
            result.0 |= bit.0;
        }
        if result.is_empty() {
            return Err(ContractError::new(
                ErrorCode::PermissionRequired,
                "empty path set",
            ));
        }
        Ok(result)
    }
}

impl NetworkPolicy {
    pub fn validate(self) -> Result<Self, ContractError> {
        if self.server_forwarding == ServerForwarding::Deny {
            if self.peer_path_mode != PeerPathMode::DirectOnly {
                return Err(ContractError::new(
                    ErrorCode::RelayDisabled,
                    "forwarding deny forbids relay paths",
                ));
            }
            if self.public_ingress == PublicIngress::Enabled {
                return Err(ContractError::new(
                    ErrorCode::PublicIngressDisabled,
                    "forwarding deny forbids public ingress",
                ));
            }
        }
        Ok(self)
    }
    pub fn paths(self) -> Result<PathSet, ContractError> {
        self.validate()?;
        Ok(match self.peer_path_mode {
            PeerPathMode::DirectOnly => PathSet::DIRECT,
            PeerPathMode::DirectPreferred => PathSet::BOTH,
            PeerPathMode::RelayOnly => PathSet::RELAY,
        })
    }
    pub fn may_publish(self) -> Result<(), ContractError> {
        self.validate()?;
        if self.server_forwarding != ServerForwarding::Allow
            || self.public_ingress != PublicIngress::Enabled
        {
            return Err(ContractError::new(
                ErrorCode::PublicIngressDisabled,
                "public ingress is disabled",
            ));
        }
        Ok(())
    }
}

// All seven scopes are required; absence is not interpreted as unrestricted.
#[derive(Debug, Clone, Copy)]
pub struct PolicyScopes {
    pub global: NetworkPolicy,
    pub account: PeerPathMode,
    pub device: PeerPathMode,
    pub resource: PeerPathMode,
    pub session: PeerPathMode,
    pub controller_local: PeerPathMode,
    pub host_local: PeerPathMode,
}

impl PolicyScopes {
    pub fn effective_paths(self) -> Result<PathSet, ContractError> {
        let mut paths = self.global.paths()?;
        for scope in [
            self.account,
            self.device,
            self.resource,
            self.session,
            self.controller_local,
            self.host_local,
        ] {
            let allowed = match scope {
                PeerPathMode::DirectOnly => PathSet::DIRECT,
                PeerPathMode::DirectPreferred => PathSet::BOTH,
                PeerPathMode::RelayOnly => PathSet::RELAY,
            };
            paths = paths.intersection(allowed);
        }
        if paths.is_empty() {
            return Err(ContractError::new(
                ErrorCode::PermissionRequired,
                "path policy intersection is empty",
            ));
        }
        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_twelve_global_combinations_match_contract() {
        let mut valid = 0;
        for forwarding in [ServerForwarding::Deny, ServerForwarding::Allow] {
            for mode in [
                PeerPathMode::DirectOnly,
                PeerPathMode::DirectPreferred,
                PeerPathMode::RelayOnly,
            ] {
                for ingress in [PublicIngress::Disabled, PublicIngress::Enabled] {
                    let policy = NetworkPolicy {
                        server_forwarding: forwarding,
                        peer_path_mode: mode,
                        public_ingress: ingress,
                    };
                    let expected = forwarding == ServerForwarding::Allow
                        || (mode == PeerPathMode::DirectOnly && ingress == PublicIngress::Disabled);
                    assert_eq!(policy.validate().is_ok(), expected);
                    valid += usize::from(expected);
                }
            }
        }
        assert_eq!(valid, 7);
        assert_eq!(NetworkPolicy::default().paths(), Ok(PathSet::DIRECT));
    }
    #[test]
    fn every_scope_can_restrict_but_never_expand_paths() {
        let modes = [
            PeerPathMode::DirectOnly,
            PeerPathMode::DirectPreferred,
            PeerPathMode::RelayOnly,
        ];
        for bits in 0_u32..729 {
            let mut index = bits;
            let mut scopes = [PeerPathMode::DirectOnly; 6];
            for scope in &mut scopes {
                *scope = modes[(index % 3) as usize];
                index /= 3;
            }
            let policy = PolicyScopes {
                global: NetworkPolicy {
                    server_forwarding: ServerForwarding::Allow,
                    peer_path_mode: PeerPathMode::DirectPreferred,
                    public_ingress: PublicIngress::Disabled,
                },
                account: scopes[0],
                device: scopes[1],
                resource: scopes[2],
                session: scopes[3],
                controller_local: scopes[4],
                host_local: scopes[5],
            };
            let direct = !scopes.contains(&PeerPathMode::RelayOnly);
            let relay = !scopes.contains(&PeerPathMode::DirectOnly);
            match policy.effective_paths() {
                Ok(paths) => {
                    assert_eq!(paths.contains(Path::Direct), direct);
                    assert_eq!(paths.contains(Path::Relay), relay);
                }
                Err(_) => assert!(!direct && !relay),
            }
        }
    }
    #[test]
    fn direct_only_remote_can_coexist_with_authorized_public_tunnels() {
        let policy = NetworkPolicy {
            server_forwarding: ServerForwarding::Allow,
            peer_path_mode: PeerPathMode::DirectOnly,
            public_ingress: PublicIngress::Enabled,
        };
        assert_eq!(policy.paths(), Ok(PathSet::DIRECT));
        assert!(policy.may_publish().is_ok());
    }
}
