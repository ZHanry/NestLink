use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand, ValueEnum};
use nestlink_auth::{VaultKey, random_bytes, random_id};
use nestlink_identity::PermitSigner;
use nestlink_operations::{
    backup::{DeploymentBackup, MAX_ARCHIVE_BYTES},
    deployment::DeploymentLease,
    upgrade::{self, MigrationRequest, Recovery},
};
use nestlink_platform_security::{create_key, create_private, load_key, read_private};
use nestlink_server::{AppState, config::ServerConfig, router};
use nestlink_storage::Store;
use std::{net::SocketAddr, path::PathBuf};
use zeroize::Zeroizing;

mod turn_node;

#[derive(Parser)]
#[command(version, about = "NestLink isolated control and data-node service")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Explicitly initialize a new deployment for the current installation generation.
    /// Retained deployments from older installations are never opened or imported.
    InstalledInit {
        #[arg(long, default_value = "/var/lib/nestlink-v15")]
        state_root: PathBuf,
        #[arg(long)]
        management_origin: String,
        #[arg(long, default_value = "127.0.0.1:28740")]
        listen: SocketAddr,
        #[arg(long)]
        allow_loopback_http: bool,
    },
    /// Run only the explicitly initialized deployment of the current installation.
    InstalledControl {
        #[arg(long, default_value = "/var/lib/nestlink-v15")]
        state_root: PathBuf,
        /// Private JSON policy; grants no authority outside its exact internal scope.
        #[arg(long)]
        internal_software_media_candidate: Option<PathBuf>,
    },
    /// Create a dedicated node identity and a pinned control configuration.
    NodeInit {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        deployment: String,
        #[arg(long)]
        control_origin: String,
        #[arg(long, allow_hyphen_values = true)]
        trusted_policy_issuer: String,
        #[arg(long, value_delimiter = ',', default_value = "relay")]
        roles: Vec<DataRole>,
        #[arg(long)]
        allow_loopback_http: bool,
    },
    /// Run authenticated short-lease node control; data services attach separately.
    NodeControl {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run pinned service QUIC and ingress for an approved edge namespace.
    NodeEdge {
        #[arg(long)]
        config: PathBuf,
        /// Exact JSON view returned by the administrator service-namespace API.
        #[arg(long)]
        namespace: PathBuf,
        #[arg(long, default_value = "0.0.0.0:29199")]
        quic_listen: SocketAddr,
        #[arg(long, default_value = "0.0.0.0")]
        ingress_ip: std::net::IpAddr,
        /// Private Caddy configuration enables HTTP/HTTPS publication.
        #[arg(long)]
        caddy_config: Option<PathBuf>,
    },
    /// Generate dedicated Caddy JSON without replacing existing files.
    CaddyBootstrap {
        #[arg(long)]
        caddy_config: PathBuf,
        #[arg(long)]
        namespace: PathBuf,
        #[arg(long, default_value = "127.0.0.1:28740")]
        management_upstream: SocketAddr,
        #[arg(long)]
        web_root: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Run independent opaque WSS and QUIC datagram relays.
    Relay {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "127.0.0.1:28746")]
        listen: SocketAddr,
        #[arg(long, default_value = "0.0.0.0:28743")]
        quic_listen: SocketAddr,
    },
    /// Run managed TURN listeners attached to an authenticated relay node lease.
    NodeTurn {
        #[arg(long)]
        config: PathBuf,
        /// TURN listener and relay-pool configuration; defaults to turn.toml beside node.toml.
        #[arg(long)]
        turn_config: Option<PathBuf>,
    },
    /// Create a new deployment. Refuses to replace any existing configuration or keys.
    Init {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        management_origin: String,
        #[arg(long, default_value = "127.0.0.1:28740")]
        listen: SocketAddr,
        #[arg(long)]
        allow_loopback_http: bool,
    },
    /// Create the first administrator; password is read from a private file.
    Bootstrap {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password_file: PathBuf,
    },
    /// Validate configuration, database namespace and OS-protected keys.
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    /// Consistent password-encrypted backup; refuses to replace an output file.
    Backup {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        password_file: PathBuf,
    },
    /// Restore offline to a NEW private directory; old tickets and recovery codes expire.
    Restore {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        expected_deployment: String,
        #[arg(long)]
        password_file: PathBuf,
    },
    /// Export known accounting lower bounds while restored control is stopped.
    QuotaRecoveryRequest {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Reconcile a restored deployment with a separately trusted external ledger.
    QuotaReconcile {
        #[arg(long)]
        config: PathBuf,
        /// Independently provisioned raw Ed25519 public key outside this deployment.
        #[arg(long)]
        trusted_ledger_key: PathBuf,
        #[arg(long)]
        proof: PathBuf,
    },
    /// Inspect schema without migrating or admitting business.
    Schema {
        #[arg(long)]
        config: PathBuf,
    },
    /// Offline forward schema migration, after a consistent authenticated backup.
    Migrate {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        from_schema: i32,
        #[arg(long)]
        to_schema: i32,
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        password_file: PathBuf,
        /// Keep schema admission fenced until a package owner commits binaries.
        #[arg(long)]
        defer_admission: bool,
    },
    /// Recover only a still-fenced transaction; cannot replay an admitted backup.
    RecoverMigration {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        transaction: String,
        #[arg(
            long,
            conflicts_with = "rollback",
            required_unless_present = "rollback"
        )]
        complete: bool,
        #[arg(
            long,
            conflicts_with = "complete",
            required_unless_present = "complete"
        )]
        rollback: bool,
    },
    /// Run the control API behind the configured Caddy origin.
    Control {
        #[arg(long)]
        config: PathBuf,
        /// Private JSON policy; absent preserves default-closed signed media rollout.
        #[arg(long)]
        internal_software_media_candidate: Option<PathBuf>,
    },
    /// Run bounded STUN address discovery; this grants no forwarding allocation.
    Stun {
        #[arg(long, default_value = "0.0.0.0:28744")]
        listen: SocketAddr,
    },
}
#[derive(Clone, ValueEnum)]
enum DataRole {
    Relay,
    Edge,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("warn,nestlink_server=info")
            }),
        )
        .json()
        .init();
    if let Err(error) = run().await {
        eprintln!("NestLink: {error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut installed_startup = None;
    let command = match Cli::parse().command {
        Command::InstalledInit {
            state_root,
            management_origin,
            listen,
            allow_loopback_http,
        } => {
            let startup = nestlink_local_ipc::maintenance::InstallationStartup::acquire(
                &std::env::current_exe()?,
            )?;
            if startup.active_instance_id()?.is_none() {
                return Err("installed-init requires a marked active v15 installation".into());
            }
            let directory = startup.state_directory(&state_root)?;
            installed_startup = Some(startup);
            Command::Init {
                directory,
                management_origin,
                listen,
                allow_loopback_http,
            }
        }
        Command::InstalledControl {
            state_root,
            internal_software_media_candidate,
        } => {
            let startup = nestlink_local_ipc::maintenance::InstallationStartup::acquire(
                &std::env::current_exe()?,
            )?;
            if startup.active_instance_id()?.is_none() {
                return Err("installed-control requires a marked active v15 installation".into());
            }
            let config = startup.state_directory(&state_root)?.join("server.toml");
            installed_startup = Some(startup);
            Command::Control {
                config,
                internal_software_media_candidate,
            }
        }
        command => command,
    };
    match command {
        Command::InstalledInit { .. } | Command::InstalledControl { .. } => {
            unreachable!("normalized above")
        }
        Command::NodeInit {
            directory,
            deployment,
            control_origin,
            trusted_policy_issuer,
            roles,
            allow_loopback_http,
        } => {
            let mut roles: Vec<_> = roles
                .into_iter()
                .map(|role| match role {
                    DataRole::Relay => nestlink_protocol::NodeRole::NodeRelay as i32,
                    DataRole::Edge => nestlink_protocol::NodeRole::NodeEdge as i32,
                })
                .collect();
            roles.sort();
            roles.dedup();
            let config = nestlink_node::control::NodeConfig {
                deployment_id: deployment,
                node_id: random_id(),
                control_origin,
                trusted_policy_issuer,
                identity_key_file: "node.key".into(),
                service_usage_directory: None,
                roles: roles.clone(),
                allow_loopback_http,
            };
            config.validate()?;
            nestlink_platform_security::new_private_directory(&directory)?;
            let seed = Zeroizing::new(random_bytes::<32>());
            let identity = nestlink_identity::nodes::NodeIdentity::from_seed(&seed);
            create_key(&directory.join("node.key"), &seed)?;
            create_private(
                &directory.join("node.toml"),
                toml::to_string_pretty(&config)?.as_bytes(),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&nestlink_protocol::api::NodeRegistration {
                    id: config.node_id,
                    name: "data-node".into(),
                    public_key: URL_SAFE_NO_PAD.encode(identity.public_key()),
                    roles,
                    max_connections: 128,
                    bytes_per_second: 16 * 1024 * 1024
                })?
            );
            eprintln!(
                "Register this public descriptor through the administrator node API before starting node-control or relay."
            );
        }
        Command::NodeControl { config } => {
            let config = nestlink_node::control::NodeConfig::load(&config)?;
            let identity = nestlink_identity::nodes::NodeIdentity::from_seed(&*load_key(
                &config.identity_key_file,
            )?);
            let control = nestlink_node::control::NodeControl::start(config, identity)?;
            tokio::select! {result=control.finish()=>result?,_=shutdown()=>{}}
        }
        Command::NodeEdge {
            config,
            namespace,
            quic_listen,
            ingress_ip,
            caddy_config,
        } => {
            let config = nestlink_node::control::NodeConfig::load(&config)?;
            if !config
                .roles
                .contains(&(nestlink_protocol::NodeRole::NodeEdge as i32))
            {
                return Err("node configuration does not enable edge role".into());
            }
            let bytes = read_private(&namespace, 32 * 1024)?;
            let namespace: nestlink_protocol::service_plane::publication::ServiceEdgeNamespaceView =
                serde_json::from_slice(&bytes)?;
            namespace.config.validate()?;
            if namespace.node_id != config.node_id {
                return Err("edge namespace belongs to a different node".into());
            }
            let caddy_config = caddy_config
                .as_deref()
                .map(nestlink_server::service_edge::caddy::CaddyServiceConfig::load)
                .transpose()?;
            if caddy_config
                .as_ref()
                .is_some_and(|caddy| caddy.deployment_id != config.deployment_id)
            {
                return Err("Caddy configuration belongs to a different deployment".into());
            }
            let seed = load_key(&config.identity_key_file)?;
            let identity =
                std::sync::Arc::new(nestlink_identity::nodes::NodeIdentity::from_seed(&seed));
            let endpoint = nestlink_transport_quic::service::listener(quic_listen, &identity)
                .map_err(std::io::Error::other)?;
            let control = std::sync::Arc::new(nestlink_node::control::NodeControl::start(
                config,
                nestlink_identity::nodes::NodeIdentity::from_seed(&seed),
            )?);
            let result = nestlink_server::service_edge::serve_with_caddy(
                endpoint,
                control.clone(),
                identity,
                namespace,
                ingress_ip,
                caddy_config,
                shutdown(),
            )
            .await;
            control.stop();
            result?;
        }
        Command::CaddyBootstrap {
            caddy_config,
            namespace,
            management_upstream,
            web_root,
            output,
        } => {
            let config =
                nestlink_server::service_edge::caddy::CaddyServiceConfig::load(&caddy_config)?;
            let bytes = read_private(&namespace, 32 * 1024)?;
            let namespace = serde_json::from_slice(&bytes)?;
            let json = config.bootstrap(&namespace, management_upstream, &web_root)?;
            create_private(&output, &serde_json::to_vec_pretty(&json)?)?;
            println!(
                "Dedicated Caddy configuration created; validate and load it before node-edge starts."
            );
        }
        Command::Relay {
            config,
            listen,
            quic_listen,
        } => {
            let config = nestlink_node::control::NodeConfig::load(&config)?;
            if !config
                .roles
                .contains(&(nestlink_protocol::NodeRole::NodeRelay as i32))
            {
                return Err("node configuration does not enable relay role".into());
            }
            let identity_seed = load_key(&config.identity_key_file)?;
            let identity = nestlink_identity::nodes::NodeIdentity::from_seed(&identity_seed);
            let listener_identity =
                nestlink_identity::nodes::NodeIdentity::from_seed(&identity_seed);
            let topology_reporter =
                std::sync::Arc::new(nestlink_node::control::TopologyReporter::new(
                    config.clone(),
                    nestlink_identity::nodes::NodeIdentity::from_seed(&identity_seed),
                )?);
            drop(identity_seed);
            let listener = tokio::net::TcpListener::bind(listen).await?;
            let control = std::sync::Arc::new(nestlink_node::control::NodeControl::start(
                config, identity,
            )?);
            let mut quic_owner = nestlink_transport_quic::routed::node_listener_with_legacy(
                quic_listen,
                &listener_identity,
                control.clone(),
            )
            .map_err(std::io::Error::other)?;
            let selector = nestlink_server::relay_selector::RelaySelector::new(control.clone());
            let (stop, stopped) = tokio::sync::watch::channel(false);
            let mut tasks = tokio::task::JoinSet::new();
            let wss_selector = selector.clone();
            let mut wss_stop = stopped.clone();
            tasks.spawn(async move {
                nestlink_server::node_relay::serve_with_selector(
                    listener,
                    wss_selector,
                    async move {
                        if !*wss_stop.borrow() {
                            let _ = wss_stop.changed().await;
                        }
                    },
                )
                .await
            });
            let endpoint = quic_owner.endpoint()?.clone();
            let mut quic_stop = stopped;
            tasks.spawn(async move {
                nestlink_server::node_quic::serve_with_topology_identity(
                    endpoint,
                    selector,
                    std::sync::Arc::new(listener_identity),
                    topology_reporter,
                    async move {
                        if !*quic_stop.borrow() {
                            let _ = quic_stop.changed().await;
                        }
                    },
                )
                .await
            });
            let result = tokio::select! {
                result = tasks.join_next() => match result {
                    Some(Ok(result)) => result,
                    Some(Err(error)) => Err(std::io::Error::other(error)),
                    None => Err(std::io::Error::other("node services ended")),
                },
                _ = shutdown() => Ok(()),
            };
            let close_deadline = tokio::time::Instant::now()
                + std::time::Duration::from_millis(nestlink_protocol::NODE_RELAY_CLOSE_IO_DRAIN_MS);
            stop.send_replace(true);
            control.stop();
            quic_owner.request_close();
            while !tasks.is_empty() {
                let joined = tokio::time::timeout_at(close_deadline, tasks.join_next())
                    .await
                    .map_err(std::io::Error::other)?;
                if let Some(joined) = joined {
                    let _ = joined.map_err(std::io::Error::other)?;
                }
            }
            quic_owner.close_and_wait(close_deadline).await?;
            result?;
        }
        Command::NodeTurn {
            config,
            turn_config,
        } => {
            turn_node::run(&config, turn_config.as_deref()).await?;
        }
        Command::Init {
            directory,
            management_origin,
            listen,
            allow_loopback_http,
        } => {
            match nestlink_platform_security::new_private_directory(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    nestlink_platform_security::check_private_directory(&directory)?
                }
                Err(error) => return Err(error.into()),
            }
            let config_path = directory.join("server.toml");
            for name in ["server.toml", "vault.key", "permit.key", "control.sqlite3"] {
                if directory.join(name).exists() {
                    return Err(
                        "deployment directory already contains NestLink state; refusing overwrite"
                            .into(),
                    );
                }
            }
            let config = ServerConfig {
                deployment_id: random_id(),
                listen,
                database: "control.sqlite3".into(),
                vault_key_file: "vault.key".into(),
                permit_key_file: "permit.key".into(),
                management_origin,
                allow_loopback_http,
                stun_servers: Vec::new(),
                allow_pcp_mapping: false,
            };
            config.validate()?;
            create_key(
                &directory.join("vault.key"),
                &Zeroizing::new(random_bytes::<32>()),
            )?;
            create_key(
                &directory.join("permit.key"),
                &Zeroizing::new(random_bytes::<32>()),
            )?;
            create_private(&config_path, toml::to_string_pretty(&config)?.as_bytes())?;
            let config = ServerConfig::load(&config_path)?;
            // SQLite creation inherits this process's umask on Unix. Create
            // its empty file with mode0600 before SQLite initializes it.
            create_private(&config.database, &[])?;
            let _store = Store::open(&config.database, &config.deployment_id)?;
            println!("Deployment initialized: {}", config.deployment_id);
            println!(
                "Create the first account with bootstrap --config <server.toml> --username <name> --password-file <private-file>."
            );
        }
        Command::Bootstrap {
            config,
            username,
            password_file,
        } => {
            let _deployment = DeploymentLease::operation(&deployment_directory(&config)?)?;
            let config = ServerConfig::load(&config)?;
            require_current_schema(&config)?;
            let _vault = load_key(&config.vault_key_file)?;
            let _signer = load_key(&config.permit_key_file)?;
            let bytes = read_private(&password_file, 1026)?;
            let password = std::str::from_utf8(&bytes)?.trim_end_matches(['\r', '\n']);
            let mut store = Store::open_existing(&config.database, &config.deployment_id)?;
            let id = store.bootstrap_admin(&username, password)?;
            println!("Administrator created: {id}");
        }
        Command::Check { config } => {
            let _deployment = DeploymentLease::operation(&deployment_directory(&config)?)?;
            let config = ServerConfig::load(&config)?;
            require_current_schema(&config)?;
            let _vault = load_key(&config.vault_key_file)?;
            let permit = load_key(&config.permit_key_file)?;
            let store = Store::open_existing(&config.database, &config.deployment_id)?;
            let (revision, _) = store.policy()?;
            println!("Configuration and deployment validated; policy revision {revision}.");
            println!(
                "Node policy issuer: {}",
                URL_SAFE_NO_PAD.encode(
                    PermitSigner::from_seed(*permit)
                        .node_policy_signer()?
                        .public_key()
                )
            );
        }
        Command::Backup {
            config,
            output,
            password_file,
        } => {
            let _deployment = DeploymentLease::operation(&deployment_directory(&config)?)?;
            let mut config = ServerConfig::load(&config)?;
            let vault = load_key(&config.vault_key_file)?;
            let permit = load_key(&config.permit_key_file)?;
            let database = config.database.clone();
            let schema = Store::existing_schema(&database, &config.deployment_id)?;
            config.use_local_state_paths();
            let backup = DeploymentBackup::capture_existing(
                &database,
                &config.deployment_id,
                schema,
                toml::to_string_pretty(&config)?.as_bytes(),
                &vault,
                &permit,
            )?;
            let password = backup_password(&password_file)?;
            let archive = backup.encrypt(&password)?;
            create_private(&output, &archive)?;
            println!(
                "Encrypted backup created for deployment {}.",
                config.deployment_id
            );
        }
        Command::Restore {
            input,
            directory,
            expected_deployment,
            password_file,
        } => {
            let archive = read_private(&input, MAX_ARCHIVE_BYTES as u64)?;
            let password = backup_password(&password_file)?;
            let backup = DeploymentBackup::decrypt(&archive, &password, &expected_deployment)?;
            let mut config: ServerConfig =
                toml::from_str(std::str::from_utf8(&backup.configuration)?)?;
            config.validate()?;
            if config.deployment_id != backup.deployment_id {
                return Err("backup configuration deployment mismatch".into());
            }
            config.use_local_state_paths();
            backup.restore_new(&directory, toml::to_string_pretty(&config)?.as_bytes())?;
            println!(
                "Deployment {} restored offline. Sign in again, verify the deployment configuration, and review device and service approvals; start control explicitly after reviewing server.toml.",
                backup.deployment_id
            );
        }
        Command::Stun { listen } => {
            let socket = tokio::net::UdpSocket::bind(listen).await?;
            println!(
                "NestLink STUN discovery listening on {}",
                socket.local_addr()?
            );
            let (_keep, receiver) = tokio::sync::watch::channel(false);
            tokio::select! {result=nestlink_traversal::server::serve(socket,receiver)=>result?,_=shutdown()=>{}}
        }
        Command::QuotaRecoveryRequest { config, output } => {
            let _deployment = DeploymentLease::runtime(&deployment_directory(&config)?)?;
            let config = ServerConfig::load(&config)?;
            require_current_schema(&config)?;
            let mut store = Store::open_existing(&config.database, &config.deployment_id)?;
            let request = store.service_quota_recovery_request()?;
            create_private(&output, &serde_json::to_vec_pretty(&request)?)?;
            println!("Restored accounting request exported: {}",
                URL_SAFE_NO_PAD.encode(nestlink_identity::service_quota_recovery::service_quota_recovery_request_digest(&request)?));
        }
        Command::QuotaReconcile {
            config,
            trusted_ledger_key,
            proof,
        } => {
            use nestlink_identity::service_quota_recovery::verify_service_quota_reconciliation;
            use nestlink_protocol::service_quota_recovery::{
                SERVICE_QUOTA_RECOVERY_BYTES, SignedServiceQuotaReconciliation,
            };
            let directory = deployment_directory(&config)?;
            let _deployment = DeploymentLease::runtime(&directory)?;
            let config = ServerConfig::load(&config)?;
            require_current_schema(&config)?;
            // The restored backup must not supply its own external trust anchor.
            if trusted_ledger_key
                .canonicalize()?
                .starts_with(directory.canonicalize()?)
            {
                return Err(
                    "external ledger key must be provisioned outside the restored deployment"
                        .into(),
                );
            }
            let trusted: [u8; 32] = read_private(&trusted_ledger_key, 32)?
                .as_slice()
                .try_into()
                .map_err(|_| "external ledger public key must contain exactly 32 raw bytes")?;
            let permit_seed = load_key(&config.permit_key_file)?;
            let permit = PermitSigner::from_seed(*permit_seed);
            if [
                permit.public_key(),
                permit.node_policy_signer()?.public_key(),
                permit.service_lease_signer()?.public_key(),
            ]
            .contains(&trusted)
            {
                return Err(
                    "external ledger key cannot be a restored deployment signing key".into(),
                );
            }
            let bytes = read_private(&proof, (SERVICE_QUOTA_RECOVERY_BYTES * 6) as u64)?;
            let signed: SignedServiceQuotaReconciliation = serde_json::from_slice(&bytes)?;
            let mut store = Store::open_existing(&config.database, &config.deployment_id)?;
            let request = store.service_quota_recovery_request()?;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis()
                .try_into()?;
            let verified =
                verify_service_quota_reconciliation(&signed, &trusted, &request, now_ms)?;
            // Retain the exact signed evidence before the atomic accounting commit.
            let retained = directory.join(format!(
                "quota-reconciliation-{}.json",
                URL_SAFE_NO_PAD.encode(verified.claims_sha256())
            ));
            let canonical = serde_json::to_vec_pretty(&signed)?;
            match create_private(&retained, &canonical) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if read_private(&retained, (SERVICE_QUOTA_RECOVERY_BYTES * 6) as u64)?
                        .as_slice()
                        != canonical
                    {
                        return Err(
                            "retained reconciliation proof differs from this statement".into()
                        );
                    }
                }
                Err(error) => return Err(error.into()),
            }
            store.reconcile_service_quota_after_restore(&verified, now_ms)?;
            println!(
                "External lifetime accounting reconciled; evidence retained at {}. Device approvals and publication recovery remain independent.",
                retained.display()
            );
        }
        Command::Schema { config } => {
            let _deployment = DeploymentLease::operation(&deployment_directory(&config)?)?;
            let config = ServerConfig::load(&config)?;
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"deployment_id":config.deployment_id,"schema":Store::existing_schema(&config.database,&config.deployment_id)?})
            );
        }
        Command::Migrate {
            config,
            from_schema,
            to_schema,
            backup,
            password_file,
            defer_admission,
        } => {
            let directory = deployment_directory(&config)?;
            if config.file_name().and_then(|name| name.to_str()) != Some("server.toml") {
                return Err("migration requires the deployment's fixed server.toml".into());
            }
            let mut configuration = ServerConfig::load(&config)?;
            for (actual, name) in [
                (&configuration.database, "control.sqlite3"),
                (&configuration.vault_key_file, "vault.key"),
                (&configuration.permit_key_file, "permit.key"),
            ] {
                if actual.canonicalize()? != directory.join(name).canonicalize()? {
                    return Err("migration requires a self-contained deployment; external state paths need an explicit reviewed relocation".into());
                }
            }
            configuration.use_local_state_paths();
            let sanitized = toml::to_string_pretty(&configuration)?;
            let password = backup_password(&password_file)?;
            let receipt = upgrade::migrate(&MigrationRequest {
                directory: &directory,
                deployment_id: &configuration.deployment_id,
                from_schema,
                to_schema,
                sanitized_configuration: sanitized.as_bytes(),
                backup: &backup,
                password: &password,
                defer_admission,
            })?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::RecoverMigration {
            directory,
            transaction,
            complete,
            rollback: _,
        } => {
            let receipt = upgrade::recover(
                &directory,
                &transaction,
                if complete {
                    Recovery::Complete
                } else {
                    Recovery::Rollback
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::Control {
            config,
            internal_software_media_candidate,
        } => {
            // Admission also covers explicitly configured installed controls.
            // Hand it to the stable deployment runtime owner before releasing
            // it, so package stop cannot deadlock on the installation gate.
            let startup = match installed_startup.take() {
                Some(startup) => startup,
                None => nestlink_local_ipc::maintenance::InstallationStartup::acquire(
                    &std::env::current_exe()?,
                )?,
            };
            let _deployment = DeploymentLease::runtime(&deployment_directory(&config)?)?;
            drop(startup);
            let config = ServerConfig::load(&config)?;
            require_current_schema(&config)?;
            let vault = VaultKey::from_bytes(*load_key(&config.vault_key_file)?);
            let signer = PermitSigner::from_seed(*load_key(&config.permit_key_file)?);
            let store = Store::open_existing(&config.database, &config.deployment_id)?;
            let store = if let Some(path) = internal_software_media_candidate {
                let bytes = read_private(&path, 16 * 1024)?;
                store.with_internal_software_media_candidate(serde_json::from_slice(&bytes)?)?
            } else {
                store
            };
            let secure = config.secure_cookies();
            let state = AppState::new(store, vault, signer, config.management_origin, secure)?
                .with_stun_servers(config.stun_servers)?
                .with_pcp_mapping(config.allow_pcp_mapping);
            state.start_maintenance();
            let app = router(state.clone());
            let listener = tokio::net::TcpListener::bind(config.listen).await?;
            println!("NestLink control listening on {}", listener.local_addr()?);
            let (maintenance_stop, stop) = tokio::sync::oneshot::channel::<()>();
            let server = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                tokio::select! {_=shutdown()=>{},_=stop=>{}}
            });
            use std::future::IntoFuture;
            let server = server.into_future();
            tokio::pin!(server);
            tokio::select! {
                result=&mut server => result?,
                result=state.run_audit_maintenance() => {
                    let _=maintenance_stop.send(());
                    let _=tokio::time::timeout(std::time::Duration::from_secs(5),&mut server).await;
                    let error=result.err().ok_or("audit maintenance stopped unexpectedly")?;
                    return Err(format!("audit maintenance failed: {error}").into());
                }
            }
        }
    }
    Ok(())
}
fn deployment_directory(config: &std::path::Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let absolute = config.canonicalize()?;
    let parent = absolute.parent().ok_or("deployment config has no parent")?;
    nestlink_platform_security::check_private_directory(parent)?;
    Ok(parent.to_owned())
}
fn require_current_schema(config: &ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    if Store::existing_schema(&config.database, &config.deployment_id)?
        != nestlink_storage::SCHEMA_VERSION
    {
        return Err("deployment schema requires an offline encrypted-backup migration before business admission".into());
    }
    Ok(())
}
fn backup_password(
    path: &std::path::Path,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut bytes = read_private(path, 1026)?;
    while matches!(bytes.last(), Some(b'\r' | b'\n')) {
        bytes.pop();
    }
    if !(12..=1024).contains(&bytes.len()) {
        return Err("backup password must contain 12 to 1024 bytes".into());
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
