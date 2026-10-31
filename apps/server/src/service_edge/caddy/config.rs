use super::*;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaddyServiceConfig {
    pub deployment_id: String,
    pub admin: CaddyAdmin,
    pub public_ips: Vec<IpAddr>,
    /// An operator-selected HTTPS DNS-over-HTTPS JSON endpoint.
    pub dns_json_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_group: Option<CaddyEdgeGroupConfig>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaddyEdgeGroupConfig {
    pub group_id: String,
    pub revision: u64,
    pub aggregate_sha256: [u8; 32],
    pub ingress_ip: IpAddr,
    /// Certificates are provisioned independently for this exact service
    /// hostname on every edge; HTTP-01 is not randomly sent to another edge.
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    /// Optional operator-selected DER CA for this deployment's DNS/readiness
    /// HTTPS clients. This protected local file never comes from a group lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_root: Option<PathBuf>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaddyAdmin {
    Unix { path: PathBuf },
    LoopbackHttp { address: SocketAddr },
}
impl CaddyServiceConfig {
    pub fn load(path: &Path) -> io::Result<Self> {
        let bytes = nestlink_platform_security::read_private(path, 64 * 1024).map_err(fault)?;
        let config: Self =
            toml::from_str(std::str::from_utf8(&bytes).map_err(fault)?).map_err(fault)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> io::Result<()> {
        if !valid_id(&self.deployment_id)
            || self.public_ips.is_empty()
            || self.public_ips.len() > 8
            || self.public_ips.iter().any(|ip| !public_ip(*ip))
            || self
                .public_ips
                .iter()
                .enumerate()
                .any(|(i, ip)| self.public_ips[..i].contains(ip))
        {
            return Err(denied());
        }
        if let Some(group) = &self.edge_group
            && (!valid_id(&group.group_id)
                || !nestlink_protocol::services::revision_valid(group.revision)
                || group.aggregate_sha256 == [0; 32]
                || group.ingress_ip.is_unspecified()
                || group.ingress_ip.is_multicast()
                || matches!(group.ingress_ip,IpAddr::V4(ip) if ip.is_broadcast())
                || !group.certificate.is_absolute()
                || !group.private_key.is_absolute()
                || group.certificate == group.private_key
                || group
                    .https_root
                    .as_ref()
                    .is_some_and(|path| !path.is_absolute()))
        {
            return Err(denied());
        }
        let url = reqwest::Url::parse(&self.dns_json_endpoint).map_err(fault)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(denied());
        }
        match &self.admin {
            CaddyAdmin::LoopbackHttp { address }
                if address.ip().is_loopback() && address.port() != 0 => {}
            CaddyAdmin::Unix { path }
                if cfg!(unix)
                    && path.is_absolute()
                    && path
                        .to_str()
                        .is_some_and(|p| !p.contains(['\0', '\n', '\r']) && p.len() <= 100) => {}
            _ => return Err(denied()),
        }
        Ok(())
    }
    pub(super) fn origin(&self) -> String {
        match &self.admin {
            CaddyAdmin::Unix { .. } => "http://localhost".into(),
            CaddyAdmin::LoopbackHttp { address } => format!("http://{address}"),
        }
    }
    pub(super) fn https_client(
        &self,
        builder: reqwest::ClientBuilder,
    ) -> io::Result<reqwest::ClientBuilder> {
        match self
            .edge_group
            .as_ref()
            .and_then(|group| group.https_root.as_ref())
        {
            Some(path) => {
                let der =
                    nestlink_platform_security::read_private(path, 16 * 1024).map_err(fault)?;
                let root = reqwest::Certificate::from_der(&der).map_err(fault)?;
                Ok(builder.add_root_certificate(root))
            }
            None => Ok(builder),
        }
    }
    fn admin_listen(&self) -> io::Result<String> {
        match &self.admin {
            CaddyAdmin::Unix { path } => Ok(format!("unix/{}", path.to_str().ok_or_else(denied)?)),
            CaddyAdmin::LoopbackHttp { address } => Ok(address.to_string()),
        }
    }
    /// A dedicated Caddy instance owns 80/443. Existing management ingress is
    /// explicit and separate from the only two subtrees this edge may mutate.
    pub fn bootstrap(
        &self,
        namespace: &ServiceEdgeNamespaceView,
        management: SocketAddr,
        web_root: &Path,
    ) -> io::Result<Value> {
        self.validate()?;
        namespace.config.validate().map_err(fault)?;
        if !valid_id(&namespace.node_id)
            || !management.ip().is_loopback()
            || management.port() == 0
            || !web_root.is_absolute()
            || web_root.to_str().is_none()
        {
            return Err(denied());
        }
        let mut bootstrap = json!({
            "admin": {"listen": self.admin_listen()?, "enforce_origin": true, "origins": [self.origin()], "config": {"persist": false}},
            "apps": {"http": {"servers": {
                "nestlink_https": {
                    "listen": [":443"], "strict_sni_host": true,
                    "read_header_timeout":"2s","idle_timeout":"30s","max_header_bytes":32768,
                    "tls_connection_policies": [{}], "automatic_https": {"disable_redirects": true},
                    "routes": [root(&namespace.node_id,"https"),
                        management_route(&namespace.config.management_hostname,management,web_root)?,
                        {"handle":[{"handler":"static_response","status_code":404}],"terminal":true}]
                },
                "nestlink_http": {
                    "listen": [":80"], "automatic_https": {"disable":true},
                    "read_header_timeout":"2s","idle_timeout":"30s","max_header_bytes":32768,
                    "routes": [root(&namespace.node_id,"http"),
                        {"match":[{"host":[namespace.config.management_hostname]}],"handle":[{"handler":"static_response","headers":{"Location":["https://{http.request.host}{http.request.uri}"]},"status_code":308}],"terminal":true},
                        {"handle":[{"handler":"static_response","status_code":404}],"terminal":true}]
                }
            }},"tls":{"certificates":{"@id":certificate_id(&namespace.node_id),"automate":[]}}}
        });
        if let Some(group) = &self.edge_group {
            // Reuse the original protected file checks and let mature Caddy
            // validate PEM/key/SAN semantics. No certificate parser is added.
            nestlink_platform_security::read_private(&group.certificate, 64 * 1024)
                .map_err(fault)?;
            nestlink_platform_security::read_private(&group.private_key, 16 * 1024)
                .map_err(fault)?;
            bootstrap["apps"]["tls"]["certificates"]["load_files"] =
                json!([{"certificate":group.certificate,"key":group.private_key}]);
        }
        Ok(bootstrap)
    }
}
fn management_route(host: &str, upstream: SocketAddr, web_root: &Path) -> io::Result<Value> {
    Ok(json!({"match":[{"host":[host]}],"terminal":true,"handle":[
        {"handler":"headers","response":{"set":{
            "Strict-Transport-Security":["max-age=31536000"],"X-Content-Type-Options":["nosniff"],"Referrer-Policy":["no-referrer"],
            "Content-Security-Policy":["default-src 'self'; connect-src 'self' wss:; img-src 'self' data:; style-src 'self'; script-src 'self' 'wasm-unsafe-eval'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"]
        }}},
        {"handler":"subroute","routes":[
            {"match":[{"path":["/api/v3/*"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":upstream.to_string()}]}],"terminal":true},
            {"handle":[{"handler":"vars","root":web_root.to_str().ok_or_else(denied)?}]},
            {"match":[{"file":{"try_files":["{http.request.uri.path}","/index.html"]}}],"handle":[{"handler":"rewrite","uri":"{http.matchers.file.relative}"}]},
            {"handle":[{"handler":"file_server"}],"terminal":true}
        ]}
    ]}))
}
fn root(node: &str, scheme: &str) -> Value {
    json!({"@id":root_id(node,scheme),"handle":[{"handler":"subroute","routes":[]}]})
}
pub(super) fn root_id(node: &str, scheme: &str) -> String {
    format!("nestlink-services-{scheme}-{node}")
}
pub(super) fn certificate_id(node: &str) -> String {
    format!("nestlink-service-certificates-{node}")
}
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_multicast()
                && a != 0
                && a < 240
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0 && (c == 0 || c == 2))
                && !(a == 192 && b == 88 && c == 99)
                && !(a == 198 && (b == 18 || b == 19 || b == 51 && c == 100))
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(ip) => {
            (ip.segments()[0] & 0xe000) == 0x2000
                && !(ip.segments()[0] == 0x2001 && ip.segments()[1] < 0x200)
                && !(ip.segments()[0] == 0x2001 && ip.segments()[1] == 0xdb8)
                && !(ip.segments()[0] == 0x3fff && ip.segments()[1] < 0x1000)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires explicit NESTLINK_CADDY_BINARY; validates actual Rust-generated production bootstrap with the real Caddy executable"]
    fn actual_caddy_validates_generated_bootstrap() -> Result<(), Box<dyn std::error::Error>> {
        let config = CaddyServiceConfig {
            deployment_id: uuid::Uuid::new_v4().to_string(),
            admin: CaddyAdmin::LoopbackHttp {
                address: "127.0.0.1:2019".parse()?,
            },
            public_ips: vec!["1.1.1.1".parse()?],
            dns_json_endpoint: "https://dns.google/resolve".into(),
            edge_group: None,
        };
        let namespace = ServiceEdgeNamespaceView {
            node_id: uuid::Uuid::new_v4().to_string(),
            revision: 1,
            config: ServiceEdgeNamespace {
                service_suffix: "svc.example.test".into(),
                management_hostname: "control.example.test".into(),
                public_ports: vec![29100],
                quic_address: "1.1.1.1:29199".into(),
            },
        };
        let work = tempfile::tempdir()?;
        std::fs::write(work.path().join("index.html"), "fixture")?;
        let value = config.bootstrap(&namespace, "127.0.0.1:28740".parse()?, work.path())?;
        assert_eq!(value.pointer("/admin/config/persist"), Some(&json!(false)));
        assert_eq!(
            value.pointer("/apps/tls/certificates/automate"),
            Some(&json!([]))
        );
        let path = work.path().join("Caddy.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&value)?)?;
        let binary = std::env::var("NESTLINK_CADDY_BINARY")?;
        let mut command = std::process::Command::new(binary);
        command.args(["validate", "--config"]).arg(path);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let output = command.output()?;
        assert!(
            output.status.success(),
            "actual Caddy rejected bootstrap: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
    #[test]
    fn config_refuses_public_admin_and_nonpublic_ownership_addresses()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = CaddyServiceConfig {
            deployment_id: uuid::Uuid::new_v4().to_string(),
            admin: CaddyAdmin::LoopbackHttp {
                address: "127.0.0.1:2019".parse()?,
            },
            public_ips: vec!["1.1.1.1".parse()?],
            dns_json_endpoint: "https://dns.google/resolve".into(),
            edge_group: None,
        };
        config.validate()?;
        for address in ["0.0.0.0:2019", "1.1.1.1:2019", "127.0.0.1:0"] {
            config.admin = CaddyAdmin::LoopbackHttp {
                address: address.parse()?,
            };
            assert!(config.validate().is_err());
        }
        config.admin = CaddyAdmin::LoopbackHttp {
            address: "127.0.0.1:2019".parse()?,
        };
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "::1",
            "::ffff:1.1.1.1",
            "2001:db8::1",
            "2001:2::1",
            "2001:20::1",
            "3fff::1",
        ] {
            config.public_ips = vec![address.parse()?];
            assert!(config.validate().is_err());
        }
        Ok(())
    }
}
