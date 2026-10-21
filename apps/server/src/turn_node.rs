//! Deployment adapter between the node's signed lease and the managed TURN service.

use nestlink_node::control::{NodeConfig, NodeControl};
use nestlink_platform_security::{load_key, read_private};
use nestlink_protocol::{NodeRole, turn::valid_realm};
use nestlink_turn_service::{RelayPortPool, TurnService, TurnServiceConfig};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

const MAX_TURN_CONFIG_BYTES: u64 = 16 * 1024;
const MAX_CERTIFICATE_CHAIN_BYTES: usize = 1024 * 1024;
const MAX_CERTIFICATES: usize = 8;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TurnNodeConfig {
    realm: String,
    #[serde(default)]
    udp_bind: Option<SocketAddr>,
    #[serde(default)]
    tcp_bind: Option<SocketAddr>,
    #[serde(default)]
    tls_bind: Option<SocketAddr>,
    #[serde(default)]
    tls_certificate_file: Option<PathBuf>,
    #[serde(default)]
    tls_private_key_file: Option<PathBuf>,
    relay_port_pools: Vec<RelayPortPoolConfig>,
    #[serde(default = "default_max_connections")]
    max_connections: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RelayPortPoolConfig {
    bind_ip: IpAddr,
    public_ip: IpAddr,
    min_port: u16,
    max_port: u16,
}

fn default_max_connections() -> usize {
    128
}

impl TurnNodeConfig {
    fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = read_private(path, MAX_TURN_CONFIG_BYTES)?;
        let mut config: Self = toml::from_str(std::str::from_utf8(&bytes)?)?;
        let parent = path.parent().ok_or("TURN config has no parent directory")?;
        for file in [
            &mut config.tls_certificate_file,
            &mut config.tls_private_key_file,
        ] {
            if let Some(path) = file
                && path.is_relative()
            {
                *path = parent.join(&*path);
            }
        }
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !valid_realm(&self.realm)
            || self.relay_port_pools.is_empty()
            || self.max_connections == 0
            || self.max_connections > 16_384
            || self.tls_bind.is_some()
                != (self.tls_certificate_file.is_some() && self.tls_private_key_file.is_some())
            || self.tls_bind.is_none()
                && (self.tls_certificate_file.is_some() || self.tls_private_key_file.is_some())
        {
            return Err("invalid managed TURN node configuration".into());
        }
        Ok(())
    }

    fn service_config(&self) -> Result<TurnServiceConfig, Box<dyn std::error::Error>> {
        let tls_server_config = match self.tls_bind {
            Some(_) => Some(Arc::new(load_tls_server_config(
                self.tls_certificate_file
                    .as_deref()
                    .ok_or("TLS listener requires a certificate chain")?,
                self.tls_private_key_file
                    .as_deref()
                    .ok_or("TLS listener requires a private key")?,
            )?)),
            None => None,
        };
        let pools = self
            .relay_port_pools
            .iter()
            .map(|pool| RelayPortPool {
                bind_ip: pool.bind_ip,
                public_ip: pool.public_ip,
                min_port: pool.min_port,
                max_port: pool.max_port,
            })
            .collect();
        let config = TurnServiceConfig {
            realm: self.realm.clone(),
            udp_bind: self.udp_bind,
            tcp_bind: self.tcp_bind,
            tls_bind: self.tls_bind,
            tls_server_config,
            relay_port_pools: pools,
            max_connections: self.max_connections,
        };
        config.validate()?;
        Ok(config)
    }
}

/// Runs the data-node control owner and managed TURN listeners as one process.
/// The TURN service is bound only after NodeControl has accepted a live lease;
/// its online watch follows NodeControl's terminal lease/stop notification.
pub(crate) async fn run(
    node_config_path: &Path,
    turn_config_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let node_config = NodeConfig::load(node_config_path)?;
    if !node_config.roles.contains(&(NodeRole::NodeRelay as i32)) {
        return Err("node configuration does not enable relay role required by TURN".into());
    }
    let default_turn_path;
    let turn_config_path = match turn_config_path {
        Some(path) => path,
        None => {
            default_turn_path = node_config_path
                .parent()
                .ok_or("node config has no parent directory")?
                .join("turn.toml");
            &default_turn_path
        }
    };
    let turn_config = TurnNodeConfig::load(turn_config_path)?;
    let service_config = turn_config.service_config()?;
    let identity = nestlink_identity::nodes::NodeIdentity::from_seed(&*load_key(
        &node_config.identity_key_file,
    )?);
    let control = NodeControl::start(node_config, identity)?;
    let mut stopped = control.stopped();

    tokio::select! {
        result = wait_for_lease(&control, &mut stopped) => result?,
        _ = shutdown() => {
            control.stop();
            return Ok(());
        }
    }

    let authorization = control.turn_authorization();
    let (online_tx, online_rx) = watch::channel(true);
    let mut lease_stop = control.stopped();
    let online_signal = online_tx.clone();
    let lease_monitor = tokio::spawn(async move {
        if !*lease_stop.borrow() {
            let _ = lease_stop.changed().await;
        }
        online_signal.send_replace(false);
    });
    let (service, _service_control) =
        TurnService::bind(service_config, authorization, online_rx).await?;
    let addresses = service.listen_addresses();
    eprintln!(
        "NestLink managed TURN listening: UDP {:?}, TCP {:?}, TLS {:?}; realm {}",
        addresses.udp, addresses.tcp, addresses.tls, turn_config.realm
    );

    let control_failed = tokio::select! {
        _ = shutdown() => false,
        _ = wait_until_stopped(&mut stopped) => true,
    };
    let control_result = if control_failed {
        // Await before stop() can abort the worker and erase its error.
        control.wait_finished().await
    } else {
        control.stop();
        Ok(())
    };
    online_tx.send_replace(false);
    service.shutdown().await?;
    let _ = lease_monitor.await;
    // The stopped watch carries no reason. A control failure must not silently
    // exit with status zero after the listeners have been cleaned up.
    control_result?;
    Ok(())
}

async fn wait_for_lease(
    control: &NodeControl,
    stopped: &mut watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        if *stopped.borrow() {
            return Err("node control stopped before accepting its first live lease".into());
        }
        if control.current_lease().is_ok() {
            return Ok(());
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(50)) => {},
            changed = stopped.changed() => {
                if changed.is_err() || *stopped.borrow() {
                    return Err("node control stopped before accepting its first live lease".into());
                }
            }
        }
    }
}

async fn wait_until_stopped(stopped: &mut watch::Receiver<bool>) {
    if *stopped.borrow() {
        return;
    }
    let _ = stopped.changed().await;
}

fn load_tls_server_config(
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let certificate_bytes = read_public_file(certificate_file, MAX_CERTIFICATE_CHAIN_BYTES)?;
    let certificates = CertificateDer::pem_slice_iter(&certificate_bytes)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    if certificates.is_empty() || certificates.len() > MAX_CERTIFICATES {
        return Err("TURN TLS certificate chain must contain 1 to 8 certificates".into());
    }
    let private_key_bytes = read_private(private_key_file, MAX_CERTIFICATE_CHAIN_BYTES as u64)?;
    let private_key = PrivateKeyDer::from_pem_slice(&private_key_bytes)?;
    Ok(ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?)
}

fn read_public_file(path: &Path, maximum: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err("TURN TLS certificate file must be a regular file under 1 MiB".into());
    }
    let bytes = fs::read(path)?;
    if bytes.len() > maximum {
        return Err("TURN TLS certificate file must be a regular file under 1 MiB".into());
    }
    Ok(bytes)
}

async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
