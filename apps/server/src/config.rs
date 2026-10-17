use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub deployment_id: String,
    pub listen: SocketAddr,
    pub database: PathBuf,
    pub vault_key_file: PathBuf,
    pub permit_key_file: PathBuf,
    pub management_origin: String,
    #[serde(default)]
    pub allow_loopback_http: bool,
    #[serde(default)]
    pub stun_servers: Vec<SocketAddr>,
}
impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = nestlink_platform_security::read_private(path, 16 * 1024)?;
        let mut value: Self = toml::from_str(std::str::from_utf8(&bytes)?)?;
        value.validate()?;
        let base = path.parent().ok_or("config has no parent directory")?;
        for target in [
            &mut value.database,
            &mut value.vault_key_file,
            &mut value.permit_key_file,
        ] {
            if target.is_relative() {
                *target = base.join(&*target);
            }
        }
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        let value = self;
        nestlink_protocol::api::NativeDiscoveryConfig {
            deployment_id: value.deployment_id.clone(),
            stun_servers: value.stun_servers.clone(),
        }
        .validate()?;
        if !nestlink_protocol::valid_id(&value.deployment_id)
            || !value.listen.ip().is_loopback()
            || value.listen.port() == 0
        {
            return Err(
                "control listener must be loopback; use Caddy as the public HTTPS entry".into(),
            );
        }
        let origin = url::Url::parse(&value.management_origin)?;
        let secure = origin.scheme() == "https";
        let loopback = match origin.host() {
            Some(url::Host::Domain(name)) => name == "localhost",
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        let development = value.allow_loopback_http && origin.scheme() == "http" && loopback;
        if (!secure && !development)
            || origin.origin().ascii_serialization() != value.management_origin
            || origin.path() != "/"
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.port() == Some(0)
        {
            return Err("management_origin must be an HTTPS origin, or explicitly enabled loopback development HTTP".into());
        }
        Ok(())
    }
    pub fn secure_cookies(&self) -> bool {
        self.management_origin.starts_with("https://")
    }
    pub fn use_local_state_paths(&mut self) {
        self.database = "control.sqlite3".into();
        self.vault_key_file = "vault.key".into();
        self.permit_key_file = "permit.key".into();
    }
}
