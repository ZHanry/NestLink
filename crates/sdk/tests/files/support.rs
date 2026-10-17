use nestlink_auth::random_id;
use nestlink_identity::{InstallationIdentity, PermitSigner, digest, verify_permit};
use nestlink_policy::PathSet;
use nestlink_protocol::{Path, Permission, PermitClaims, SCHEMA_VERSION};
use nestlink_remote::{
    AuthorizedConnection, ChannelRuntime, RuntimeClock, SessionLifecycle, SessionSetup,
};
use nestlink_session::{EndpointRole, Session, SessionBinding, StopReason};
use nestlink_transport_stream::tls;
use prost::Message;
use std::{fs, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::watch;

pub(super) type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(super) struct TempDirectory {
    path: PathBuf,
    parent: PathBuf,
}
impl TempDirectory {
    pub(super) fn new() -> Result<Self> {
        let parent = std::env::temp_dir().canonicalize()?;
        let path = parent.join(format!("nestlink-sdk-files-{}", random_id()));
        fs::create_dir(&path)?;
        Ok(Self { path, parent })
    }
    pub(super) fn path(&self) -> &std::path::Path {
        &self.path
    }
}
impl Drop for TempDirectory {
    fn drop(&mut self) {
        // Delete only the exact test-owned child verified under the temporary
        // parent. A substituted path is never used for recursive cleanup.
        if self.path.parent() == Some(self.parent.as_path())
            && self
                .path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("nestlink-sdk-files-"))
            && self
                .path
                .canonicalize()
                .is_ok_and(|actual| actual == self.path)
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub(super) struct Sessions {
    pub(super) c: ChannelRuntime,
    pub(super) h: ChannelRuntime,
    pub(super) scope: ConnectionScope,
    _stops: [watch::Sender<Option<StopReason>>; 2],
}
#[derive(Clone)]
pub(super) struct ConnectionScope {
    controller_seed: [u8; 32],
    host_seed: [u8; 32],
    signer_seed: [u8; 32],
    claims: PermitClaims,
}
impl Sessions {
    pub(super) async fn new(quic: bool) -> Result<Self> {
        Self::with_scope(quic, None, 9).await
    }
    #[allow(dead_code)] // Selected only by the upload integration test target.
    pub(super) async fn new_upload(quic: bool) -> Result<Self> {
        Self::with_permissions(quic, None, 9, vec![Permission::View, Permission::FileWrite]).await
    }
    pub(super) async fn with_scope(
        quic: bool,
        previous: Option<&ConnectionScope>,
        generation: u64,
    ) -> Result<Self> {
        Self::with_permissions(
            quic,
            previous,
            generation,
            vec![Permission::View, Permission::FileRead],
        )
        .await
    }
    async fn with_permissions(
        quic: bool,
        previous: Option<&ConnectionScope>,
        generation: u64,
        permissions: Vec<Permission>,
    ) -> Result<Self> {
        let controller_seed = previous
            .map(|s| s.controller_seed)
            .unwrap_or_else(|| digest(random_id().as_bytes()));
        let host_seed = previous
            .map(|s| s.host_seed)
            .unwrap_or_else(|| digest(random_id().as_bytes()));
        let signer_seed = previous
            .map(|s| s.signer_seed)
            .unwrap_or_else(|| digest(random_id().as_bytes()));
        let controller = InstallationIdentity::from_seed(controller_seed);
        let host = InstallationIdentity::from_seed(host_seed);
        let clock = RuntimeClock::default();
        let now = clock.sample()?;
        let mut claims = previous
            .map(|s| s.claims.clone())
            .unwrap_or_else(|| PermitClaims {
                schema_version: SCHEMA_VERSION,
                deployment_id: random_id(),
                security_epoch: 1,
                session_id: random_id(),
                account_id: random_id(),
                controller_device_id: random_id(),
                host_device_id: random_id(),
                controller_key_sha256: controller.fingerprint().to_vec(),
                host_key_sha256: host.fingerprint().to_vec(),
                resource_id: random_id(),
                permissions: permissions.iter().map(|p| *p as i32).collect(),
                paths: vec![Path::Direct as i32],
                policy_revision: 1,
                connection_generation: generation,
                lease_sequence: 1,
                issued_at_unix_ms: now.unix_ms,
                expires_at_unix_ms: now.unix_ms + 15000,
                capability_sha256: vec![7; 32],
                required_capabilities: vec!["vp8".into()],
            });
        claims.connection_generation = generation;
        claims.issued_at_unix_ms = now.unix_ms;
        claims.expires_at_unix_ms = now.unix_ms + 15000;
        let signer = PermitSigner::from_seed(signer_seed);
        let permit = verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?;
        let session = || {
            Session::activate(
                permit.clone(),
                SessionBinding {
                    deployment_id: claims.deployment_id.clone(),
                    security_epoch: claims.security_epoch,
                    session_id: claims.session_id.clone(),
                    account_id: claims.account_id.clone(),
                    controller_device_id: claims.controller_device_id.clone(),
                    host_device_id: claims.host_device_id.clone(),
                    controller_key_sha256: controller.fingerprint(),
                    host_key_sha256: host.fingerprint(),
                    resource_id: claims.resource_id.clone(),
                    policy_revision: 1,
                    connection_generation: generation,
                    capability_sha256: [7; 32],
                    granted_permissions: permissions.clone(),
                    supported_capabilities: vec!["vp8".into()],
                    local_paths: PathSet::DIRECT,
                },
                Path::Direct,
                now.monotonic_ms,
                now,
            )
        };
        let (c_stop, cs) = watch::channel(None);
        let (h_stop, hs) = watch::channel(None);
        let scope = ConnectionScope {
            controller_seed,
            host_seed,
            signer_seed,
            claims: claims.clone(),
        };
        let (c, h) = if quic {
            let he = nestlink_transport_quic::listener(
                "127.0.0.1:0".parse()?,
                &host,
                controller.fingerprint(),
            )?;
            let ce = nestlink_transport_quic::connector(
                "127.0.0.1:0".parse()?,
                &controller,
                host.fingerprint(),
            )?;
            let accepted = async {
                he.accept()
                    .await
                    .ok_or("QUIC listener closed")?
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            };
            let (connected, accepted) = tokio::join!(
                nestlink_transport_quic::connect(&ce, he.local_addr()?, Duration::from_secs(3)),
                accepted
            );
            let h_key = host.public_key();
            let c_key = controller.public_key();
            let c_setup = SessionSetup {
                session: session()?,
                path: Path::Direct,
                role: EndpointRole::Controller,
                clock: clock.clone(),
                lifecycle: SessionLifecycle::new(cs),
            };
            let h_setup = SessionSetup {
                session: session()?,
                path: Path::Direct,
                role: EndpointRole::Host,
                clock,
                lifecycle: SessionLifecycle::new(hs),
            };
            let (c, h) = tokio::join!(
                nestlink_remote::quic::authorize(
                    connected?,
                    Some(ce),
                    c_setup,
                    &controller,
                    &h_key
                ),
                nestlink_remote::quic::authorize(accepted?, Some(he), h_setup, &host, &c_key)
            );
            (c?, h?)
        } else {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let cc = tokio_rustls::TlsConnector::from(Arc::new(tls::client_config(
                &controller,
                host.fingerprint(),
            )?));
            let hc = tokio_rustls::TlsAcceptor::from(Arc::new(tls::server_config(
                &host,
                controller.fingerprint(),
            )?));
            let controller_side = async {
                let io = cc
                    .connect(
                        rustls::pki_types::ServerName::try_from("peer.nestlink.invalid")?,
                        tokio::net::TcpStream::connect(address).await?,
                    )
                    .await?;
                let (mut read, mut write) = tokio::io::split(io);
                let mut session = session()?;
                nestlink_remote::controller_proof(
                    &mut read,
                    &mut write,
                    &mut session,
                    &controller,
                    &host.public_key(),
                    &clock,
                )
                .await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    AuthorizedConnection::new(
                        read,
                        write,
                        session,
                        Path::Direct,
                        clock.clone(),
                        cs,
                    )?
                    .into_channels(),
                )
            };
            let host_side = async {
                let io = hc.accept(listener.accept().await?.0).await?;
                let (mut read, mut write) = tokio::io::split(io);
                let mut session = session()?;
                nestlink_remote::host_proof(
                    &mut read,
                    &mut write,
                    &mut session,
                    &host,
                    &controller.public_key(),
                    &clock,
                )
                .await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                    AuthorizedConnection::new(
                        read,
                        write,
                        session,
                        Path::Direct,
                        clock.clone(),
                        hs,
                    )?
                    .into_channels(),
                )
            };
            let (c, h) = tokio::join!(controller_side, host_side);
            (c?, h?)
        };
        Ok(Self {
            c,
            h,
            scope,
            _stops: [c_stop, h_stop],
        })
    }
}
