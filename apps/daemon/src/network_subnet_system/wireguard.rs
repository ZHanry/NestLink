//! Optional standard WireGuard ingress for the same journaled namespace owner.
//! The kernel authenticates one independent client key and exact source /32;
//! every business packet must then cross the original TUN/packet/carrier owner.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use nestlink_identity::{
    network::{NetworkVerification, verify_network_grant},
    wireguard::{WireGuardPortalState, verify_wireguard_client_binding},
};
use nestlink_protocol::{
    network::{Direction, IpProtocol},
    wireguard::SignedWireGuardClientBinding,
};
use std::net::{Ipv4Addr, SocketAddrV4};
use zeroize::Zeroizing;
pub(super) mod owner;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ingress {
    pub binding: SignedWireGuardClientBinding,
    pub approved_binding: [u8; 32],
    pub server_public_key: [u8; 32],
    pub client_endpoint: SocketAddrV4,
    pub underlay_next_hop: Option<Ipv4Addr>,
    pub listen_port: u16,
}
impl Ingress {
    pub fn interface(plan: &Plan) -> String {
        format!("nlw{}", plan.suffix())
    }
    pub fn check(&self, plan: &Plan, checked: &plan::Checked, now: u64) -> Result {
        if !checked.local_source
            || self.listen_port == 0
            || self.client_endpoint.port() == 0
            || self.server_public_key == [0; 32]
            || self.approved_binding == [0; 32]
        {
            return Err(io::Error::other("standard WireGuard requires one original source portal and explicit public key, endpoint and approval").into());
        }
        let client = *self.client_endpoint.ip();
        if client.is_unspecified()
            || client.is_loopback()
            || client.is_multicast()
            || client.is_link_local()
            || client == plan.lan_gateway
        {
            return Err(io::Error::other(
                "concrete independent IPv4 client underlay endpoint required",
            )
            .into());
        }
        let underlay = ipnet::Ipv4Net::new(plan.lan_gateway, plan.lan_prefix_len)?;
        match self.underlay_next_hop {
            Some(next)
                if next != plan.lan_gateway
                    && next != underlay.network()
                    && next != underlay.broadcast()
                    && underlay.contains(&next) => {}
            None if underlay.contains(&client)
                && client != underlay.network()
                && client != underlay.broadcast() => {}
            _ => {
                return Err(io::Error::other(
                    "explicit same-LAN underlay next hop is required for a remote standard client",
                )
                .into());
            }
        }
        let revoked = std::collections::BTreeSet::new();
        let directory = &plan.credentials.address_directory;
        let context = NetworkVerification {
            authority_key: &plan.authority,
            deployment_id: &plan.deployment_id,
            space_id: &plan.space_id,
            policy_epoch: directory.space.policy_epoch,
            now_ms: now,
            revoked_grant_ids: &revoked,
        };
        let access = verify_network_grant(
            &nestlink_sdk::network_management::decode_network_grant(&plan.credentials.access)?,
            &context,
        )?;
        let mapping = plan
            .credentials
            .subnet_mappings
            .iter()
            .find(|mapping| mapping.gateway.public_key == plan.local_public)
            .ok_or_else(|| io::Error::other("original WireGuard source mapping missing"))?;
        let claims = nestlink_protocol::wireguard::WireGuardClientBindingClaims::decode_canonical(
            &self.binding.claims,
        )?;
        let portal = WireGuardPortalState {
            node_id: &mapping.gateway.node_id,
            public_key: &mapping.gateway.public_key,
            incarnation: &mapping.gateway.incarnation,
            lease_expires_at_ms: mapping.gateway.lease_expires_at_ms,
            client_revision: claims.client_revision,
        };
        let verified = verify_wireguard_client_binding(&self.binding, &context, access, &portal)?;
        let source = nestlink_protocol::network::IpPrefix {
            network: claims.client_address.into(),
            prefix_len: 32,
        };
        if verified.digest() != self.approved_binding
            || claims.access_digest != plan.approved_access
            || claims.portal_public_key != plan.local_public
            || claims.scope.expires_at_ms < plan.expires_at_ms
            || checked.mapping.original != source
            || checked.mapping.alias != source
            || checked.business.source_prefixes.as_slice() != [source]
            || claims.client_address == plan.lan_gateway
            || underlay.contains(&claims.client_address)
            || checked.remote.iter().any(|prefix| {
                plan::net(*prefix).is_ok_and(|network| {
                    network.contains(&client)
                        || self
                            .underlay_next_hop
                            .is_some_and(|next| network.contains(&next))
                })
            })
        {
            return Err(io::Error::other("WireGuard plan must preserve exact approved binding, original business, independent /32 and underlay separation").into());
        }
        Ok(())
    }
    /// Exact fixed configuration; no private key is returned in readback.
    pub async fn configuration(&self, plan: &Plan) -> Result<serde_json::Value> {
        let name = Self::interface(plan);
        let mut fields = serde_json::Map::new();
        for field in [
            "public-key",
            "listen-port",
            "peers",
            "allowed-ips",
            "endpoints",
            "persistent-keepalive",
        ] {
            let value =
                crate::wireguard::tools::run("wg", &["show", &name, field], &[], 4096).await?;
            fields.insert(field.into(), std::str::from_utf8(&value)?.trim_end().into());
        }
        let claims = nestlink_protocol::wireguard::WireGuardClientBindingClaims::decode_canonical(
            &self.binding.claims,
        )?;
        let peer = STANDARD.encode(claims.client_public_key);
        if fields["public-key"] != STANDARD.encode(self.server_public_key)
            || fields["listen-port"]
                .as_str()
                .and_then(|value| value.parse::<u16>().ok())
                != Some(self.listen_port)
            || fields["peers"] != peer
            || fields["allowed-ips"] != format!("{peer}\t{}/32", claims.client_address)
            || fields["endpoints"] != format!("{peer}\t{}", self.client_endpoint)
            || fields["persistent-keepalive"] != format!("{peer}\t25")
        {
            return Err(io::Error::other(
                "original WireGuard key, exact peer/address or physical endpoint changed",
            )
            .into());
        }
        let link = kernel::local_link(&name).await?;
        if link["linkinfo"]["info_kind"] != "wireguard"
            || link["ifalias"].as_str() != Some(plan.marker().as_str())
            || link["mtu"] != 1280
        {
            return Err(io::Error::other("owned WireGuard interface identity changed").into());
        }
        Ok(serde_json::json!({"link":link,"public_configuration":fields}))
    }
    pub async fn configure(&self, plan: &Plan, secret: &[u8; 32]) -> Result {
        if crate::wireguard::public_key_for(secret).await? != self.server_public_key {
            return Err(io::Error::other(
                "root-selected stable portal private key differs from explicit public approval",
            )
            .into());
        }
        let name = Self::interface(plan);
        kernel::command("ip", &["link", "add", "dev", &name, "type", "wireguard"]).await?;
        kernel::command(
            "ip",
            &[
                "link",
                "set",
                "dev",
                &name,
                "alias",
                &plan.marker(),
                "mtu",
                "1280",
                "multicast",
                "off",
                "addrgenmode",
                "none",
            ],
        )
        .await?;
        let claims = nestlink_protocol::wireguard::WireGuardClientBindingClaims::decode_canonical(
            &self.binding.claims,
        )?;
        let configuration = Zeroizing::new(format!(
            "[Interface]\nPrivateKey = {}\nListenPort = {}\n\n[Peer]\nPublicKey = {}\nAllowedIPs = {}/32\nEndpoint = {}\nPersistentKeepalive = 25\n",
            STANDARD.encode(secret),
            self.listen_port,
            STANDARD.encode(claims.client_public_key),
            claims.client_address,
            self.client_endpoint
        ));
        crate::wireguard::tools::run(
            "wg",
            &["setconf", &name, "/dev/stdin"],
            configuration.as_bytes(),
            4096,
        )
        .await?;
        let client_route = format!("{}/32", claims.client_address);
        kernel::command(
            "ip",
            &[
                "-4",
                "route",
                "add",
                &client_route,
                "dev",
                &name,
                "metric",
                "42420",
            ],
        )
        .await?;
        let outer_route = format!("{}/32", self.client_endpoint.ip());
        match self.underlay_next_hop {
            Some(next) => {
                kernel::command(
                    "ip",
                    &[
                        "-4",
                        "route",
                        "add",
                        &outer_route,
                        "via",
                        &next.to_string(),
                        "dev",
                        &plan.macvlan(),
                        "metric",
                        "42420",
                    ],
                )
                .await?;
            }
            None => {
                kernel::command(
                    "ip",
                    &[
                        "-4",
                        "route",
                        "add",
                        &outer_route,
                        "dev",
                        &plan.macvlan(),
                        "scope",
                        "link",
                        "metric",
                        "42420",
                    ],
                )
                .await?;
            }
        }
        std::fs::write(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"), b"0")?;
        kernel::command("ip", &["link", "set", "dev", &name, "up"]).await?;
        self.configuration(plan).await?;
        Ok(())
    }
    pub fn rules(&self, plan: &Plan, checked: &plan::Checked) -> Result<String> {
        let namespace = plan.namespace();
        let tun = plan.tun();
        let wg = Self::interface(plan);
        let lan = plan.macvlan();
        let claims = nestlink_protocol::wireguard::WireGuardClientBindingClaims::decode_canonical(
            &self.binding.claims,
        )?;
        let client = format!("{}/32", claims.client_address);
        let remote = checked
            .remote
            .iter()
            .map(|prefix| format!("{}/{}", prefix.network, prefix.prefix_len))
            .collect::<Vec<_>>()
            .join(", ");
        let outer = self.client_endpoint.ip();
        let port = self.client_endpoint.port();
        let own = plan.lan_gateway;
        let listen = self.listen_port;
        // Apply fragment refusal before kernel conntrack defragmentation.
        let mut rules = format!(
            "table inet {namespace} {{\nquota budget {{ {} bytes }}\nchain raw {{ type filter hook prerouting priority -450; policy accept; meta time >= {} drop; meta nfproto ipv6 drop; ip frag-off & 0x3fff != 0 drop; ip hdrlength != 5 drop; }}\nchain input {{ type filter hook input priority 0; policy drop; iifname \"{lan}\" ip saddr {outer} ip daddr {own} udp sport {port} udp dport {listen} accept; }}\nchain output {{ type filter hook output priority 0; policy drop; oifname \"{lan}\" ip saddr {own} ip daddr {outer} udp sport {listen} udp dport {port} accept; }}\nchain admitted {{ quota name budget accept; }}\nchain forward {{ type filter hook forward priority 0; policy drop; ct state invalid drop;\n",
            checked.business.byte_limit,
            plan.expires_at_ms / 1000
        );
        for (from, to, source, destination, direction) in [
            (
                &wg,
                &tun,
                client.clone(),
                format!("{{ {remote} }}"),
                Direction::Inbound,
            ),
            (
                &tun,
                &wg,
                format!("{{ {remote} }}"),
                client,
                Direction::Outbound,
            ),
        ] {
            rules.push_str(&format!("iifname \"{from}\" oifname \"{to}\" ip saddr {source} ip daddr {destination} ct state established jump admitted;\n"));
            for rule in &checked.business.rules {
                if rule.direction != direction {
                    continue;
                }
                let protocol = match rule.protocol {
                    IpProtocol::Tcp => {
                        let [low, high] = rule.ports.ok_or_else(|| {
                            io::Error::other("exact TCP WireGuard ports required")
                        })?;
                        format!(
                            "tcp dport {} tcp flags & (syn|ack|fin|rst) == syn",
                            ports(low, high)
                        )
                    }
                    IpProtocol::Udp => {
                        let [low, high] = rule.ports.ok_or_else(|| {
                            io::Error::other("exact UDP WireGuard ports required")
                        })?;
                        format!("udp dport {}", ports(low, high))
                    }
                    IpProtocol::IcmpV4 => "icmp type echo-request".into(),
                    _ => {
                        return Err(io::Error::other(
                            "this WireGuard portal requires exact original IPv4 rules",
                        )
                        .into());
                    }
                };
                rules.push_str(&format!("iifname \"{from}\" oifname \"{to}\" ip saddr {source} ip daddr {destination} {protocol} ct state new jump admitted;\n"));
            }
        }
        rules.push_str("}\n}\n");
        Ok(rules)
    }
}
fn ports(low: u16, high: u16) -> String {
    if low == high {
        low.to_string()
    } else {
        format!("{low}-{high}")
    }
}
