//! Dedicated Ubuntu IPVS-NAT fixed entry. Kernel IPVS preserves the original
//! visitor IP for the existing source ACL; no user-space proxy/parser is added.
use nestlink_protocol::{api::{ServiceDefinition,ServiceIngress},service_plane::group::ServiceEdgeGroupView,valid_id};
use serde::{Deserialize,Serialize};
use std::{io,path::Path};

#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedIngressHealth {pub node_id:String,pub port:u16}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedIngressConfig {
    pub schema_version:u32,
    pub deployment_id:String,
    pub group:ServiceEdgeGroupView,
    pub definition:ServiceDefinition,
    /// Separate original-owner HTTP readiness on each actual backend edge.
    pub health:Vec<FixedIngressHealth>,
}
fn invalid()->io::Error{io::Error::other("fixed ingress requires one explicit IPv4 VIP, the exact approved group and original-owner health ports")}
impl FixedIngressConfig {
    pub fn load(path:&Path)->io::Result<Self>{
        let bytes=nestlink_platform_security::read_private(path,64*1024)?;
        let config:Self=serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        config.validate()?;Ok(config)
    }
    pub fn validate(&self)->io::Result<()> {
        self.group.validate(&self.definition).map_err(io::Error::other)?;
        if self.schema_version!=1 || !valid_id(&self.deployment_id)
            || self.group.public_ips.len()!=1 || !self.group.public_ips[0].is_ipv4()
            || self.group.public_ips[0].is_loopback() || self.group.public_ips[0].is_unspecified()
            || self.health.len()!=self.group.members.len()
            || nestlink_identity::services::definition_digest(&self.definition).map_err(io::Error::other)?!=self.group.definition_sha256 {return Err(invalid());}
        for (member,health) in self.group.members.iter().zip(&self.health) {
            if health.node_id!=member.node_id || !member.ingress_ip.is_ipv4() || member.ingress_ip.is_loopback()
                || self.group.public_ips.contains(&member.ingress_ip) || health.port<1024 || (28743..=29055).contains(&health.port)
                || matches!(self.definition.requested_ingress,ServiceIngress::Tcp{port}|ServiceIngress::Udp{port} if port==health.port) {return Err(invalid());}
        }
        Ok(())
    }
    pub fn keepalived(&self)->io::Result<String>{
        self.validate()?;
        let protocol=if matches!(self.definition.requested_ingress,ServiceIngress::Udp{..}){"UDP"}else{"TCP"};
        let port=match &self.definition.requested_ingress{ServiceIngress::Http{..}=>80,ServiceIngress::Https{..}=>443,ServiceIngress::Tcp{port}|ServiceIngress::Udp{port}=>*port};
        let digest:String=nestlink_identity::service_plane::group::service_edge_group_digest(&self.group).map_err(io::Error::other)?.iter().map(|byte|format!("{byte:02x}")).collect();
        let mut config=format!("# Dedicated director only. No VRRP or unrelated IPVS services.\n# Group {} revision {}; existing sessions are not replicated.\nvirtual_server {} {} {{\n  delay_loop 1\n  alpha\n  lb_algo wrr\n  lb_kind NAT\n  protocol {}\n",self.group.group_id,self.group.revision,self.group.public_ips[0],port,protocol);
        for (member,health) in self.group.members.iter().zip(&self.health) {
            config.push_str(&format!("  real_server {} {} {{\n    weight 1\n    HTTP_GET {{\n      connect_port {}\n      connect_timeout 1\n      retry 1\n      delay_before_retry 1\n      url {{\n        path /service-group/{}/{}/{}\n        status_code 200\n      }}\n    }}\n  }}\n",member.ingress_ip,port,health.port,self.group.group_id,self.group.revision,digest));
        }
        config.push_str("}\n");Ok(config)
    }
    /// Generate a fresh owner-private deployment bundle; applying it remains
    /// an explicit administrator operation on a dedicated prepared director.
    pub fn write_bundle(&self,directory:&Path)->io::Result<()> {
        self.validate()?;
        if !directory.is_absolute(){return Err(invalid());}
        nestlink_platform_security::new_private_directory(directory)?;
        nestlink_platform_security::create_private(&directory.join("keepalived.conf"),self.keepalived()?.as_bytes())?;
        nestlink_platform_security::create_private(&directory.join("fixed-ingress.json"),&serde_json::to_vec_pretty(self).map_err(io::Error::other)?)?;
        nestlink_platform_security::create_private(&directory.join("BOUNDARIES.txt"),b"IPVS-NAT preserves client source IP. Use a dedicated Ubuntu director with one preconfigured IPv4 VIP and no unrelated IPVS services. Edges must route replies through the director. Enable forwarding and the documented IPVS destination-expiry settings explicitly before applying. Run the Actions-shipped installer and verify actual HTTP/HTTPS/TCP/UDP bytes and failure timing. Per-edge health is not fixed-entry acceptance. Existing connections/sessions may break on edge loss. This bundle grants no edge publication or local target authority. DNS-only, IPv6 VIPs, TLS certificate provisioning and director HA are outside this first deployment mode.\n")?;
        Ok(())
    }
}
