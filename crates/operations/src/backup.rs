//! Versioned password-encrypted deployment backup. Unauthenticated lengths and
//! KDF parameters are rejected before expensive work or SQLite parsing.
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use nestlink_auth::random_bytes;
use nestlink_storage::{StorageError, Store, snapshot::MAX_SNAPSHOT_BYTES};
use std::{io, path::Path};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAGIC: &[u8; 8] = b"NL15BA01";
const HEADER_LEN: usize = 64;
pub const MAX_CONFIG_BYTES: usize = 16 * 1024;
pub const MAX_ARCHIVE_BYTES: usize =
    HEADER_LEN + 16 + 36 + 64 + 4 + MAX_CONFIG_BYTES + 8 + MAX_SNAPSHOT_BYTES;
const MEMORY_KIB: u32 = 65_536;
const ITERATIONS: u32 = 3;
const LANES: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("invalid backup format, size or password length")]
    Format,
    #[error("backup authentication failed")]
    Authentication,
    #[error("backup deployment does not match the expected deployment")]
    Deployment,
    #[error("backup cryptographic operation failed")]
    Crypto,
    #[error("backup storage: {0}")]
    Storage(#[from] StorageError),
    #[error("backup filesystem: {0}")]
    Io(#[from] io::Error),
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeploymentBackup {
    pub deployment_id: String,
    pub configuration: Vec<u8>,
    pub vault_key: [u8; 32],
    pub permit_seed: [u8; 32],
    pub database: Vec<u8>,
}
impl DeploymentBackup {
    pub fn capture(
        store: &Store,
        configuration: &[u8],
        vault_key: &[u8; 32],
        permit_seed: &[u8; 32],
    ) -> Result<Self, BackupError> {
        if configuration.is_empty() || configuration.len() > MAX_CONFIG_BYTES {
            return Err(BackupError::Format);
        }
        Ok(Self {
            deployment_id: store.deployment_id()?,
            configuration: configuration.to_vec(),
            vault_key: *vault_key,
            permit_seed: *permit_seed,
            database: store.snapshot()?.to_vec(),
        })
    }

    /// Capture an existing deployment before any schema write can occur.
    pub fn capture_existing(
        path: &Path,
        deployment_id: &str,
        expected_schema: i32,
        configuration: &[u8],
        vault_key: &[u8; 32],
        permit_seed: &[u8; 32],
    ) -> Result<Self, BackupError> {
        if configuration.is_empty() || configuration.len() > MAX_CONFIG_BYTES {
            return Err(BackupError::Format);
        }
        Ok(Self {
            deployment_id: deployment_id.to_owned(),
            configuration: configuration.to_vec(),
            vault_key: *vault_key,
            permit_seed: *permit_seed,
            database: Store::snapshot_existing(path, deployment_id, expected_schema)?.to_vec(),
        })
    }

    /// Isolated upgrade staging preserves current authority/epoch/recovery codes.
    /// The distinct restore_new path continues to revoke old restore credentials.
    pub fn restore_for_migration_new(
        &self,
        directory: &Path,
        sanitized_configuration: &[u8],
    ) -> Result<(), BackupError> {
        if sanitized_configuration.is_empty() || sanitized_configuration.len() > MAX_CONFIG_BYTES {
            return Err(BackupError::Format);
        }
        let store = Store::from_snapshot(&self.database, &self.deployment_id)?;
        let database = store.snapshot()?;
        nestlink_platform_security::new_private_directory(directory)?;
        nestlink_platform_security::create_private(&directory.join("control.sqlite3"), &database)?;
        nestlink_platform_security::create_key(&directory.join("vault.key"), &self.vault_key)?;
        nestlink_platform_security::create_key(&directory.join("permit.key"), &self.permit_seed)?;
        nestlink_platform_security::create_private(
            &directory.join("server.toml"),
            sanitized_configuration,
        )?;
        Ok(())
    }

    pub fn encrypt(&self, password: &[u8]) -> Result<Vec<u8>, BackupError> {
        validate_password(password)?;
        if !nestlink_protocol::valid_id(&self.deployment_id)
            || self.deployment_id.len() != 36
            || self.configuration.is_empty()
            || self.configuration.len() > MAX_CONFIG_BYTES
            || !(100..=MAX_SNAPSHOT_BYTES).contains(&self.database.len())
        {
            return Err(BackupError::Format);
        }
        let mut plain = Zeroizing::new(Vec::with_capacity(
            112 + self.configuration.len() + self.database.len(),
        ));
        plain.extend_from_slice(self.deployment_id.as_bytes());
        plain.extend_from_slice(&self.vault_key);
        plain.extend_from_slice(&self.permit_seed);
        plain.extend_from_slice(&(self.configuration.len() as u32).to_be_bytes());
        plain.extend_from_slice(&self.configuration);
        plain.extend_from_slice(&(self.database.len() as u64).to_be_bytes());
        plain.extend_from_slice(&self.database);
        let mut header = [0u8; HEADER_LEN];
        header[..8].copy_from_slice(MAGIC);
        header[8..12].copy_from_slice(&MEMORY_KIB.to_be_bytes());
        header[12..16].copy_from_slice(&ITERATIONS.to_be_bytes());
        header[16..20].copy_from_slice(&LANES.to_be_bytes());
        header[20..36].copy_from_slice(&random_bytes::<16>());
        header[36..60].copy_from_slice(&random_bytes::<24>());
        header[60..64].copy_from_slice(&((plain.len() + 16) as u32).to_be_bytes());
        let key = derive(password, &header[20..36])?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&header[36..60]),
                Payload {
                    msg: &plain,
                    aad: &header,
                },
            )
            .map_err(|_| BackupError::Crypto)?;
        let mut archive = Vec::with_capacity(HEADER_LEN + encrypted.len());
        archive.extend_from_slice(&header);
        archive.extend_from_slice(&encrypted);
        Ok(archive)
    }

    pub fn decrypt(
        archive: &[u8],
        password: &[u8],
        expected_deployment: &str,
    ) -> Result<Self, BackupError> {
        validate_password(password)?;
        if !nestlink_protocol::valid_id(expected_deployment) {
            return Err(BackupError::Deployment);
        }
        if !(HEADER_LEN + 16 + 112 + 1 + 100..=MAX_ARCHIVE_BYTES).contains(&archive.len())
            || &archive[..8] != MAGIC
            || number(&archive[8..12])? != MEMORY_KIB
            || number(&archive[12..16])? != ITERATIONS
            || number(&archive[16..20])? != LANES
            || number(&archive[60..64])? as usize != archive.len() - HEADER_LEN
        {
            return Err(BackupError::Format);
        }
        let key = derive(password, &archive[20..36])?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&archive[36..60]),
                    Payload {
                        msg: &archive[HEADER_LEN..],
                        aad: &archive[..HEADER_LEN],
                    },
                )
                .map_err(|_| BackupError::Authentication)?,
        );
        let mut reader = Reader(&plain);
        let deployment_id =
            std::str::from_utf8(reader.take(36)?).map_err(|_| BackupError::Format)?;
        if deployment_id != expected_deployment {
            return Err(BackupError::Deployment);
        }
        let vault_key: Zeroizing<[u8; 32]> = Zeroizing::new(
            reader
                .take(32)?
                .try_into()
                .map_err(|_| BackupError::Format)?,
        );
        let permit_seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            reader
                .take(32)?
                .try_into()
                .map_err(|_| BackupError::Format)?,
        );
        let config_len = number(reader.take(4)?)? as usize;
        if !(1..=MAX_CONFIG_BYTES).contains(&config_len) {
            return Err(BackupError::Format);
        }
        let configuration = reader.take(config_len)?;
        let db_len = u64::from_be_bytes(
            reader
                .take(8)?
                .try_into()
                .map_err(|_| BackupError::Format)?,
        );
        if !(100..=MAX_SNAPSHOT_BYTES as u64).contains(&db_len) {
            return Err(BackupError::Format);
        }
        let database = reader.take(db_len as usize)?;
        if !reader.0.is_empty() {
            return Err(BackupError::Format);
        }
        Ok(Self {
            deployment_id: deployment_id.to_owned(),
            configuration: configuration.to_vec(),
            vault_key: *vault_key,
            permit_seed: *permit_seed,
            database: database.to_vec(),
        })
    }

    /// Caller validates and sanitizes application config before creating output.
    /// Writes only these fixed filenames into an exclusively created directory.
    /// Its parent must be trusted and not writable by untrusted users.
    pub fn restore_new(
        &self,
        directory: &Path,
        sanitized_configuration: &[u8],
    ) -> Result<u64, BackupError> {
        if sanitized_configuration.is_empty() || sanitized_configuration.len() > MAX_CONFIG_BYTES {
            return Err(BackupError::Format);
        }
        let mut store = Store::from_snapshot(&self.database, &self.deployment_id)?;
        let epoch = store.invalidate_after_restore()?;
        let database = store.snapshot()?;
        nestlink_platform_security::new_private_directory(directory)?;
        // No activation config until all database and key writes have synced.
        nestlink_platform_security::create_private(&directory.join("control.sqlite3"), &database)?;
        nestlink_platform_security::create_key(&directory.join("vault.key"), &self.vault_key)?;
        nestlink_platform_security::create_key(&directory.join("permit.key"), &self.permit_seed)?;
        nestlink_platform_security::create_private(
            &directory.join("server.toml"),
            sanitized_configuration,
        )?;
        Ok(epoch)
    }
}
fn validate_password(password: &[u8]) -> Result<(), BackupError> {
    if !(12..=1024).contains(&password.len()) {
        return Err(BackupError::Format);
    }
    Ok(())
}
fn derive(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    let params =
        Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(32)).map_err(|_| BackupError::Crypto)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, &mut *key)
        .map_err(|_| BackupError::Crypto)?;
    Ok(key)
}
fn number(bytes: &[u8]) -> Result<u32, BackupError> {
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| BackupError::Format)?,
    ))
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], BackupError> {
        if count > self.0.len() {
            return Err(BackupError::Format);
        }
        let (part, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(part)
    }
}
