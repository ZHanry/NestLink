//! Typed local subnet configuration after independent mapping and IP business
//! verification. This module creates no TUN, route, NAT, forwarding or socket.
//! The online owner must consume its original start claim and bind its path
//! before a privileged adapter may apply this immutable plan.
use ipnet::IpNet;
use nestlink_identity::{network::{NetworkVerification, VerifiedNetworkGrant}, subnet::{SubnetGatewayState, VerifiedSubnetMapping}};
use nestlink_protocol::{network::{GrantClaims, IpPrefix}, subnet::MAX_SUBNET_MAPPINGS, valid_id};
use serde::Serialize;
use std::{io, net::IpAddr, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

const OBSERVATION_MS: u64 = 5000;
const MAX_OWNER_MS: u64 = 60_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SubnetInterface {
    pub index: u32,
    pub name: String,
}
impl SubnetInterface {
    fn validate(&self) -> io::Result<()> {
        if self.index == 0 || self.name.is_empty() || self.name.len() > 15
            || !self.name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || matches!(self.name.as_str(), "." | ".." | "lo")
        { return Err(denied("an exact non-loopback interface name and index are required")); }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SubnetInterfaces {
    pub tun: SubnetInterface,
    pub lan: SubnetInterface,
}

/// Created only by the explicit local approval flow. A downloaded mapping or
/// JSON file cannot deserialize this choice or approve a later alias revision.
pub struct SubnetLocalConsent {
    owner_id: String,
    mapping_digest: [u8; 32],
    access_digest: [u8; 32],
}
impl SubnetLocalConsent {
    pub fn approve(owner_id: String, mapping_digest: [u8; 32], access_digest: [u8; 32]) -> io::Result<Self> {
        if !valid_id(&owner_id) || mapping_digest == [0; 32] || access_digest == [0; 32] {
            return Err(denied("subnet consent requires the original owner and both exact approved digests"));
        }
        Ok(Self { owner_id, mapping_digest, access_digest })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubnetTranslation {
    RouteOnly,
    Ipv4PrefixNat,
}
#[derive(Debug, Serialize)]
pub struct SubnetPlanView {
    pub owner_id: String,
    pub space_id: String,
    pub gateway_node_id: String,
    pub mapping_revision: u64,
    pub mapping_digest: [u8; 32],
    pub access_digest: [u8; 32],
    pub original: IpPrefix,
    pub alias: IpPrefix,
    pub interfaces: SubnetInterfaces,
    pub translation: SubnetTranslation,
    pub expires_at_ms: u64,
}

/// No Clone/Deserialize and no packet-budget constructor: this is a checked OS
/// configuration intent, not permission to create a second business owner.
pub struct VerifiedSubnetPlan {
    view: SubnetPlanView,
    mapping: VerifiedSubnetMapping,
    access: VerifiedNetworkGrant,
    deadline: Instant,
}
impl VerifiedSubnetPlan {
    pub fn new(
        context: &NetworkVerification<'_>,
        gateway: &SubnetGatewayState<'_>,
        mapping: VerifiedSubnetMapping,
        access: VerifiedNetworkGrant,
        consent: SubnetLocalConsent,
        interfaces: SubnetInterfaces,
        physical_endpoints: &[IpAddr],
    ) -> io::Result<Self> {
        let now = fresh_time(context)?;
        let current = current(context, now);
        mapping.check_current(&current, gateway).map_err(denied)?;
        access.check_current(&current).map_err(denied)?;
        interfaces.tun.validate()?;
        interfaces.lan.validate()?;
        if interfaces.tun.index == interfaces.lan.index || interfaces.tun.name == interfaces.lan.name {
            return Err(denied("subnet TUN and original LAN interfaces must be distinct"));
        }
        let claims = mapping.claims();
        let GrantClaims::NetworkAccess(business) = access.claims() else {
            return Err(denied("subnet forwarding requires independently signed NetworkAccess"));
        };
        let (own, remote) = if business.source == claims.gateway {
            (&business.source_prefixes, &business.destination_prefixes)
        } else if business.destination == claims.gateway {
            (&business.destination_prefixes, &business.source_prefixes)
        } else { return Err(denied("NetworkAccess does not name this authenticated gateway")); };
        if consent.mapping_digest != mapping.digest() || consent.access_digest != access.digest()
            || business.source == business.destination || own.as_slice() != [claims.alias]
            || business.scope.grant_id == claims.scope.grant_id
            || business.scope.grant_id == mapping.route_export().claims().scope().grant_id
        { return Err(denied("subnet consent, exact wire prefix or business identity differs")); }
        let alias = prefix(claims.alias)?;
        for value in remote {
            if overlaps(alias, prefix(*value)?) { return Err(denied("subnet grant would reflect a wire prefix to the same gateway")); }
        }
        let remote_prefixes = remote.iter().copied().map(prefix).collect::<io::Result<Vec<_>>>()?;
        if physical_endpoints.is_empty() || physical_endpoints.len() > 8
            || physical_endpoints.iter().any(|ip| ip.is_unspecified() || ip.is_multicast()
                || alias.contains(ip) || remote_prefixes.iter().any(|network| network.contains(ip)))
        { return Err(denied("subnet alias route could capture an original physical carrier endpoint")); }
        let expires_at_ms = mapping.effective_expires_at_ms(gateway)
            .min(business.scope.expires_at_ms).min(now.saturating_add(MAX_OWNER_MS));
        let remaining = expires_at_ms.checked_sub(now).filter(|value| *value > 0)
            .ok_or_else(|| denied("subnet plan has no remaining original lifetime"))?;
        let translation = if claims.original == claims.alias { SubnetTranslation::RouteOnly } else { SubnetTranslation::Ipv4PrefixNat };
        let view = SubnetPlanView { owner_id: consent.owner_id, space_id: claims.scope.space_id.clone(),
            gateway_node_id: claims.gateway_node_id.clone(), mapping_revision: claims.mapping_revision,
            mapping_digest: mapping.digest(), access_digest: access.digest(), original: claims.original,
            alias: claims.alias, interfaces, translation, expires_at_ms };
        Ok(Self { view, mapping, access, deadline: Instant::now() + Duration::from_millis(remaining) })
    }
    pub fn view(&self) -> &SubnetPlanView { &self.view }
    /// Fresh management must also confirm the exact stored mapping/access pair.
    /// This cryptographic check cannot invent that online database association.
    pub fn check_current(&self, context: &NetworkVerification<'_>, gateway: &SubnetGatewayState<'_>) -> io::Result<()> {
        let now = fresh_time(context)?;
        if Instant::now() >= self.deadline || now >= self.view.expires_at_ms { return Err(denied("original subnet plan expired")); }
        let current = current(context, now);
        self.mapping.check_current(&current, gateway).map_err(denied)?;
        self.access.check_current(&current).map_err(denied)
    }
    /// Bounded nftables syntax for the future journaled privileged adapter.
    /// The installed kernel performs prefix translation, checksums and NAT
    /// state. These statements alone are not a firewall or apply operation.
    pub fn nft_ipv4_translation(&self) -> Option<[String; 2]> {
        if self.view.translation != SubnetTranslation::Ipv4PrefixNat { return None; }
        let tun = &self.view.interfaces.tun;
        let original = format!("{}/{}", self.view.original.network, self.view.original.prefix_len);
        let alias = format!("{}/{}", self.view.alias.network, self.view.alias.prefix_len);
        Some([
            format!("meta iif {} meta iifname \"{}\" ip daddr {alias} dnat ip prefix to ip daddr map {{ {alias} : {original} }}", tun.index, tun.name),
            format!("meta oif {} meta oifname \"{}\" ip saddr {original} snat ip prefix to ip saddr map {{ {original} : {alias} }}", tun.index, tun.name),
        ])
    }
}

/// Aliases occupy one space-wide namespace. Two different sites may export
/// the same original LAN; their aliases must remain unambiguous. Primary/standby
/// ownership requires a separate explicit group contract and is not inferred.
pub fn check_mapping_conflicts(mappings: &[VerifiedSubnetMapping], reserved: &[IpPrefix]) -> io::Result<()> {
    if mappings.is_empty() || mappings.len() > MAX_SUBNET_MAPPINGS || reserved.len() > 128 {
        return Err(denied("subnet mapping or reserved prefix set exceeds its bound"));
    }
    let first = &mappings[0].claims().scope;
    for (index, mapping) in mappings.iter().enumerate() {
        let claims = mapping.claims();
        if claims.scope.space_id != first.space_id || claims.scope.deployment_id != first.deployment_id || claims.scope.policy_epoch != first.policy_epoch {
            return Err(denied("subnet mapping set crosses a space or policy boundary"));
        }
        let alias = prefix(claims.alias)?;
        for protected in reserved {
            if overlaps(alias, prefix(*protected)?) { return Err(denied("subnet alias conflicts with a local, virtual or protected route")); }
        }
        for other in &mappings[..index] {
            let other = other.claims();
            if claims.scope.grant_id == other.scope.grant_id || overlaps(alias, prefix(other.alias)?)
                || overlaps(alias, prefix(other.original)?) || overlaps(prefix(other.alias)?, prefix(claims.original)?)
                || (claims.gateway == other.gateway && overlaps(prefix(claims.original)?, prefix(other.original)?))
            { return Err(denied("ambiguous subnet alias, original gateway prefix or mapping identity")); }
        }
    }
    Ok(())
}
fn prefix(value: IpPrefix) -> io::Result<IpNet> {
    value.validate().map_err(denied)?;
    IpNet::new(value.network, value.prefix_len).map_err(denied)
}
fn overlaps(a: IpNet, b: IpNet) -> bool { a.contains(&b.addr()) || b.contains(&a.addr()) }
fn fresh_time(context: &NetworkVerification<'_>) -> io::Result<u64> {
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).map_err(denied)?.as_millis()).map_err(denied)?;
    if context.now_ms > now || now - context.now_ms >= OBSERVATION_MS { return Err(denied("subnet plan requires a fresh pinned management observation")); }
    Ok(now)
}
fn current<'a>(context: &NetworkVerification<'a>, now_ms: u64) -> NetworkVerification<'a> {
    NetworkVerification { authority_key: context.authority_key, deployment_id: context.deployment_id, space_id: context.space_id,
        policy_epoch: context.policy_epoch, now_ms, revoked_grant_ids: context.revoked_grant_ids }
}
fn denied(reason: impl std::fmt::Display) -> io::Error { io::Error::new(io::ErrorKind::PermissionDenied, reason.to_string()) }

#[cfg(test)]
mod tests;
