//! Offline schema upgrades: authenticated backup, isolated migration, then swap.
//!
//! Recovery is possible only while the migration journal still fences business.
//! Once a new runtime has been admitted, an older backup must never be replayed
//! as a downgrade: it could resurrect revoked authority or old quota balances.
use crate::{
    backup::{BackupError, DeploymentBackup, MAX_ARCHIVE_BYTES},
    deployment::MigrationOwner,
};
use nestlink_platform_security::{check_private_directory, create_private, load_key, read_private};
use nestlink_storage::{SCHEMA_VERSION, StorageError, Store};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io, path::Path};

pub type UpgradeResult<T> = Result<T, UpgradeError>;
#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    #[error("deployment is in use; stop control and wait for its real lifetime owner")]
    Busy,
    #[error("an incomplete schema transaction requires explicit recovery")]
    Incomplete,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("migration filesystem: {0}")]
    Io(#[from] io::Error),
    #[error("migration storage: {0}")]
    Storage(#[from] StorageError),
    #[error("migration backup: {0}")]
    Backup(#[from] BackupError),
    #[error("migration metadata is invalid")]
    Metadata(#[from] serde_json::Error),
    #[error("activation failed and the exact pre-upgrade directory was restored")]
    RolledBack,
}

pub struct MigrationRequest<'a> {
    pub directory: &'a Path,
    pub deployment_id: &'a str,
    pub from_schema: i32,
    pub to_schema: i32,
    pub sanitized_configuration: &'a [u8],
    pub backup: &'a Path,
    pub password: &'a [u8],
    /// Package owners keep the deployment fenced until binary/receipt commit.
    pub defer_admission: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryProof {
    schema: i32,
    snapshot_sha256: String,
    configuration_sha256: String,
    vault_sha256: String,
    permit_sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u16,
    purpose: String,
    transaction_id: String,
    deployment_id: String,
    active_name: String,
    candidate_name: String,
    previous_name: String,
    phase: String,
    old: DirectoryProof,
    new: DirectoryProof,
    archive_sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationReceipt {
    pub schema_version: u16,
    pub transaction_id: String,
    pub deployment_id: String,
    pub from_schema: i32,
    pub to_schema: i32,
    pub archive_sha256: String,
    pub old_snapshot_sha256: String,
    pub new_snapshot_sha256: String,
    pub previous_directory: String,
}
#[derive(Clone, Copy)]
pub enum Recovery {
    Rollback,
    Complete,
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn fixed_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn sync_parent(path: &Path) -> UpgradeResult<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(windows)]
    let _ = path; // Each new file is FlushFileBuffers'd; replacements use write-through MoveFileEx.
    Ok(())
}

fn atomic_journal(path: &Path, value: &Journal, create: bool) -> UpgradeResult<()> {
    let raw = serde_json::to_vec(value)?;
    if create {
        create_private(path, &raw)?;
    } else {
        let current: Journal = serde_json::from_slice(&read_private(path, 16 * 1024)?)?;
        if current.transaction_id != value.transaction_id {
            return Err(UpgradeError::Invalid("migration journal owner changed"));
        }
        // A visible journal still fences the transaction. Continue only after
        // confirming durability; recovery can inspect the committed phase.
        if nestlink_platform_security::replace_private_metadata(path, &raw)?
            != nestlink_platform_security::MetadataCommit::Durable
        {
            return Err(UpgradeError::Io(io::Error::other(
                "migration journal committed but durability is unconfirmed",
            )));
        }
    }
    sync_parent(
        path.parent()
            .ok_or(UpgradeError::Invalid("journal parent unavailable"))?,
    )
}

fn prove(directory: &Path, deployment: &str, schema: i32) -> UpgradeResult<DirectoryProof> {
    check_private_directory(directory)?;
    let config = read_private(&directory.join("server.toml"), 16 * 1024)?;
    let vault = load_key(&directory.join("vault.key"))?;
    let permit = load_key(&directory.join("permit.key"))?;
    // Reject linked/private-widened DB handles before SQLite can open them.
    let metadata = fs::symlink_metadata(directory.join("control.sqlite3"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(UpgradeError::Invalid(
            "migration database is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(UpgradeError::Invalid(
                "migration database permissions are not private",
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(UpgradeError::Invalid(
                "migration database is a reparse point",
            ));
        }
    }
    let snapshot =
        Store::snapshot_existing(&directory.join("control.sqlite3"), deployment, schema)?;
    Ok(DirectoryProof {
        schema,
        snapshot_sha256: digest(&snapshot),
        configuration_sha256: digest(&config),
        vault_sha256: digest(vault.as_ref()),
        permit_sha256: digest(permit.as_ref()),
    })
}
fn same_proof(actual: &DirectoryProof, expected: &DirectoryProof) -> bool {
    actual.schema == expected.schema
        && actual.snapshot_sha256 == expected.snapshot_sha256
        && actual.configuration_sha256 == expected.configuration_sha256
        && actual.vault_sha256 == expected.vault_sha256
        && actual.permit_sha256 == expected.permit_sha256
}
fn require_proof(directory: &Path, deployment: &str, proof: &DirectoryProof) -> UpgradeResult<()> {
    if !same_proof(&prove(directory, deployment, proof.schema)?, proof) {
        return Err(UpgradeError::Invalid(
            "migration directory contents differ from their recorded proof",
        ));
    }
    Ok(())
}
fn exists(path: &Path) -> UpgradeResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            check_private_directory(path)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn move_directory(source: &Path, destination: &Path) -> UpgradeResult<()> {
    check_private_directory(source)?;
    if fs::symlink_metadata(destination).is_ok() {
        return Err(UpgradeError::Invalid(
            "migration destination already exists",
        ));
    }
    // rename fails on a cross-filesystem boundary. No recursive copy or delete.
    fs::rename(source, destination)?;
    sync_parent(source.parent().ok_or(UpgradeError::Invalid(
        "migration directory parent unavailable",
    ))?)
}
fn clear_journal(owner: &MigrationOwner, journal: &Journal, action: Recovery) -> UpgradeResult<()> {
    let path = owner.locations.journal();
    let current: Journal = serde_json::from_slice(&read_private(&path, 16 * 1024)?)?;
    if current.transaction_id != journal.transaction_id {
        return Err(UpgradeError::Invalid(
            "migration journal owner changed before completion",
        ));
    }
    // Durable terminal state precedes removal. If a deletion reappears after a
    // power loss, recovery must never replay a pre-admission snapshot over
    // data that may already contain new revocations or quota accounting.
    let mut terminal = journal.clone();
    terminal.phase = match action {
        Recovery::Complete => "completed",
        Recovery::Rollback => "rolled-back",
    }
    .into();
    atomic_journal(&path, &terminal, false)?;
    fs::remove_file(path)?;
    sync_parent(&owner.locations.parent)
}
fn receipt(journal: &Journal) -> MigrationReceipt {
    MigrationReceipt {
        schema_version: 1,
        transaction_id: journal.transaction_id.clone(),
        deployment_id: journal.deployment_id.clone(),
        from_schema: journal.old.schema,
        to_schema: journal.new.schema,
        archive_sha256: journal.archive_sha256.clone(),
        old_snapshot_sha256: journal.old.snapshot_sha256.clone(),
        new_snapshot_sha256: journal.new.snapshot_sha256.clone(),
        previous_directory: journal.previous_name.clone(),
    }
}

/// All schema changes happen in a new sibling. Before activation, the archive
/// is create-new, flushed, re-read, authenticated and compared with the source.
pub fn migrate(request: &MigrationRequest<'_>) -> UpgradeResult<MigrationReceipt> {
    let owner = MigrationOwner::acquire(request.directory, false)?;
    if request.to_schema != SCHEMA_VERSION
        || request.from_schema < 4
        || request.from_schema >= request.to_schema
        || !nestlink_protocol::valid_id(request.deployment_id)
    {
        return Err(UpgradeError::Invalid(
            "only a supported forward migration to this binary's current schema is allowed",
        ));
    }
    if !request.backup.is_absolute() || request.backup.starts_with(request.directory) {
        return Err(UpgradeError::Invalid(
            "encrypted backup must be an absolute new file outside the active deployment",
        ));
    }
    let backup_parent = request
        .backup
        .parent()
        .ok_or(UpgradeError::Invalid("backup has no parent"))?;
    check_private_directory(backup_parent)?;
    if backup_parent
        .canonicalize()?
        .starts_with(request.directory.canonicalize()?)
    {
        return Err(UpgradeError::Invalid(
            "backup parent resolves inside the active deployment",
        ));
    }
    let old = prove(
        request.directory,
        request.deployment_id,
        request.from_schema,
    )?;
    let vault = load_key(&request.directory.join("vault.key"))?;
    let permit = load_key(&request.directory.join("permit.key"))?;
    let backup = DeploymentBackup::capture_existing(
        &request.directory.join("control.sqlite3"),
        request.deployment_id,
        request.from_schema,
        request.sanitized_configuration,
        &vault,
        &permit,
    )?;
    if digest(&backup.database) != old.snapshot_sha256 {
        return Err(UpgradeError::Invalid(
            "deployment changed before encrypted capture",
        ));
    }
    let encrypted = backup.encrypt(request.password)?;
    create_private(request.backup, &encrypted)?;
    let readback = read_private(request.backup, MAX_ARCHIVE_BYTES as u64)?;
    let authenticated =
        DeploymentBackup::decrypt(&readback, request.password, request.deployment_id)?;
    if authenticated.database != backup.database
        || authenticated.configuration != backup.configuration
        || authenticated.vault_key != backup.vault_key
        || authenticated.permit_seed != backup.permit_seed
        || digest(&readback) != digest(&encrypted)
    {
        return Err(UpgradeError::Invalid(
            "encrypted backup readback differs from captured deployment",
        ));
    }
    let transaction_id = nestlink_auth::random_id();
    let candidate_name = format!("{}.candidate-{}", owner.locations.prefix, transaction_id);
    let previous_name = format!("{}.previous-{}", owner.locations.prefix, transaction_id);
    let candidate = owner.locations.parent.join(&candidate_name);
    authenticated.restore_for_migration_new(&candidate, request.sanitized_configuration)?;
    let new = prove(&candidate, request.deployment_id, request.to_schema)?;
    if old.vault_sha256 != new.vault_sha256 || old.permit_sha256 != new.permit_sha256 {
        return Err(UpgradeError::Invalid(
            "schema migration changed deployment keys",
        ));
    }
    let journal = Journal {
        schema_version: 1,
        purpose: "deployment-schema-migration".into(),
        transaction_id,
        deployment_id: request.deployment_id.into(),
        active_name: owner.locations.name.clone(),
        candidate_name,
        previous_name,
        phase: "prepared".into(),
        old,
        new,
        archive_sha256: digest(&encrypted),
    };
    create_private(
        &candidate.join("migration-receipt.json"),
        &serde_json::to_vec(&receipt(&journal))?,
    )?;
    sync_parent(&candidate)?;
    // Recheck exact source and candidate immediately before the durable fence.
    require_proof(request.directory, request.deployment_id, &journal.old)?;
    require_proof(&candidate, request.deployment_id, &journal.new)?;
    atomic_journal(&owner.locations.journal(), &journal, true)?;
    match recover_owned(
        &owner,
        &journal,
        Recovery::Complete,
        !request.defer_admission,
    ) {
        Ok(()) => Ok(receipt(&journal)),
        Err(_activation_error) => {
            // No business can pass the stable exclusive gate or pending journal.
            // Restore exact original bytes, rather than migrating them again.
            recover_owned(&owner, &journal, Recovery::Rollback, true)?;
            Err(UpgradeError::RolledBack)
        }
    }
}

fn read_journal(owner: &MigrationOwner, expected_transaction: &str) -> UpgradeResult<Journal> {
    let journal: Journal =
        serde_json::from_slice(&read_private(&owner.locations.journal(), 16 * 1024)?)?;
    if journal.schema_version != 1
        || journal.purpose != "deployment-schema-migration"
        || !nestlink_protocol::valid_id(&journal.transaction_id)
        || journal.transaction_id != expected_transaction
        || !nestlink_protocol::valid_id(&journal.deployment_id)
        || journal.active_name != owner.locations.name
        || journal.candidate_name
            != format!(
                "{}.candidate-{}",
                owner.locations.prefix, journal.transaction_id
            )
        || journal.previous_name
            != format!(
                "{}.previous-{}",
                owner.locations.prefix, journal.transaction_id
            )
        || !matches!(
            journal.phase.as_str(),
            "prepared" | "old-moved" | "new-activated" | "completed" | "rolled-back"
        )
        || journal.old.schema < 4
        || journal.old.schema >= journal.new.schema
        || journal.new.schema != SCHEMA_VERSION
        || !fixed_hash(&journal.archive_sha256)
    {
        return Err(UpgradeError::Invalid(
            "migration recovery identity, directory or schema is invalid",
        ));
    }
    for proof in [&journal.old, &journal.new] {
        if ![
            &proof.snapshot_sha256,
            &proof.configuration_sha256,
            &proof.vault_sha256,
            &proof.permit_sha256,
        ]
        .iter()
        .all(|value| fixed_hash(value))
        {
            return Err(UpgradeError::Invalid("migration proof is malformed"));
        }
    }
    Ok(journal)
}

/// Exact explicit crash recovery. A missing journal refuses any restore,
/// including an attempt to replay an old pre-revocation backup after admission.
pub fn recover(
    directory: &Path,
    expected_transaction: &str,
    action: Recovery,
) -> UpgradeResult<MigrationReceipt> {
    let owner = MigrationOwner::acquire(directory, true)?;
    let journal = read_journal(&owner, expected_transaction)?;
    recover_owned(&owner, &journal, action, true)?;
    Ok(receipt(&journal))
}

fn recover_owned(
    owner: &MigrationOwner,
    original: &Journal,
    action: Recovery,
    finalize: bool,
) -> UpgradeResult<()> {
    let active = owner.locations.active();
    let candidate = owner.locations.parent.join(&original.candidate_name);
    let previous = owner.locations.parent.join(&original.previous_name);
    let mut journal = original.clone();
    if matches!(journal.phase.as_str(), "completed" | "rolled-back") {
        let proof = match (journal.phase.as_str(), action) {
            ("completed", Recovery::Complete) => &journal.new,
            ("rolled-back", Recovery::Rollback) => &journal.old,
            _ => {
                return Err(UpgradeError::Invalid(
                    "terminal migration recovery cannot switch direction after possible business admission",
                ));
            }
        };
        let actual = prove(&active, &journal.deployment_id, proof.schema)?;
        if actual.configuration_sha256 != proof.configuration_sha256
            || actual.vault_sha256 != proof.vault_sha256
            || actual.permit_sha256 != proof.permit_sha256
        {
            return Err(UpgradeError::Invalid(
                "terminal migration deployment metadata changed; explicit review is required",
            ));
        }
        return clear_journal(owner, &journal, action);
    }
    let layout = (exists(&active)?, exists(&candidate)?, exists(&previous)?);
    match layout {
        (true, true, false) => {
            require_proof(&active, &journal.deployment_id, &journal.old)?;
            require_proof(&candidate, &journal.deployment_id, &journal.new)?;
            if matches!(action, Recovery::Complete) {
                move_directory(&active, &previous)?;
                journal.phase = "old-moved".into();
                atomic_journal(&owner.locations.journal(), &journal, false)?;
                move_directory(&candidate, &active)?;
                journal.phase = "new-activated".into();
                atomic_journal(&owner.locations.journal(), &journal, false)?;
                require_proof(&active, &journal.deployment_id, &journal.new)?;
            }
        }
        (false, true, true) => {
            require_proof(&previous, &journal.deployment_id, &journal.old)?;
            require_proof(&candidate, &journal.deployment_id, &journal.new)?;
            match action {
                Recovery::Rollback => move_directory(&previous, &active)?,
                Recovery::Complete => move_directory(&candidate, &active)?,
            }
        }
        (true, false, true) => {
            require_proof(&active, &journal.deployment_id, &journal.new)?;
            require_proof(&previous, &journal.deployment_id, &journal.old)?;
            if matches!(action, Recovery::Rollback) {
                move_directory(&active, &candidate)?;
                move_directory(&previous, &active)?;
            }
        }
        _ => {
            return Err(UpgradeError::Invalid(
                "migration directory layout is ambiguous; retained journal requires operator review",
            ));
        }
    }
    let expected = match action {
        Recovery::Rollback => &journal.old,
        Recovery::Complete => &journal.new,
    };
    require_proof(&active, &journal.deployment_id, expected)?;
    if !finalize {
        journal.phase = "new-activated".into();
        return atomic_journal(&owner.locations.journal(), &journal, false);
    }
    clear_journal(owner, &journal, action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment::{DeploymentLease, Locations};
    use nestlink_storage::APPLICATION_ID;
    use rusqlite::{Connection, params};
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    const PASSWORD: &[u8] = b"migration-owned-fixture-password";

    struct Fixture {
        _temporary: tempfile::TempDir,
        parent: std::path::PathBuf,
        directory: std::path::PathBuf,
        deployment: String,
    }
    impl Fixture {
        fn new() -> TestResult<Self> {
            let temporary = tempfile::tempdir()?;
            let parent = temporary.path().join("private-parent");
            nestlink_platform_security::new_private_directory(&parent)?;
            let directory = parent.join("deployment");
            nestlink_platform_security::new_private_directory(&directory)?;
            create_private(
                &directory.join("server.toml"),
                b"fixture original config bytes",
            )?;
            nestlink_platform_security::create_key(&directory.join("vault.key"), &[4; 32])?;
            nestlink_platform_security::create_key(&directory.join("permit.key"), &[5; 32])?;
            create_private(&directory.join("control.sqlite3"), &[])?;
            let connection = Connection::open(directory.join("control.sqlite3"))?;
            for sql in [
                include_str!("../../storage/migrations/001_initial.sql"),
                include_str!("../../storage/migrations/002_control.sql"),
                include_str!("../../storage/migrations/003_policy_scopes.sql"),
                include_str!("../../storage/migrations/004_signaling.sql"),
            ] {
                connection.execute_batch(sql)?;
            }
            let deployment = nestlink_auth::random_id();
            connection.execute("INSERT INTO deployment VALUES(1,?1,17,1,?2)",params![deployment,"{\"path_mode\":\"direct_only\",\"allow_lan\":true,\"allow_wan_direct\":true,\"allow_relay\":true}"])?;
            // Policy JSON is subsequently validated through the production Store;
            // use a current empty deployment's canonical default, not a test copy.
            let defaults = Store::in_memory(&nestlink_auth::random_id())?;
            let snapshot = defaults.snapshot()?;
            let mut view = Connection::open_in_memory()?;
            view.deserialize_read_exact(
                rusqlite::MAIN_DB,
                snapshot.as_slice(),
                snapshot.len(),
                true,
            )?;
            let policy: String =
                view.query_row("SELECT policy_json FROM deployment", [], |row| row.get(0))?;
            connection.execute("UPDATE deployment SET policy_json=?1", [policy])?;
            let account = nestlink_auth::random_id();
            connection.execute(
                "INSERT INTO accounts(id,name) VALUES(?1,'retained-account')",
                [&account],
            )?;
            connection.execute("INSERT INTO recovery_codes(account_id,code_sha256,consumed) VALUES(?1,?2,0),(?1,?3,1)",params![account,[6u8;32].as_slice(),[7u8;32].as_slice()])?;
            connection.pragma_update(None, "application_id", APPLICATION_ID)?;
            connection.pragma_update(None, "user_version", 4)?;
            drop(connection);
            Ok(Self {
                _temporary: temporary,
                parent,
                directory,
                deployment,
            })
        }
        fn request(&self, defer: bool) -> MigrationRequest<'_> {
            MigrationRequest {
                directory: &self.directory,
                deployment_id: &self.deployment,
                from_schema: 4,
                to_schema: SCHEMA_VERSION,
                sanitized_configuration: b"fixture sanitized config bytes",
                backup: Path::new("/invalid-placeholder"),
                password: PASSWORD,
                defer_admission: defer,
            }
        }
        fn migrate(&self, defer: bool) -> TestResult<MigrationReceipt> {
            let backup = self.parent.join("upgrade-backup.nl15");
            let mut request = self.request(defer);
            request.backup = &backup;
            Ok(migrate(&request)?)
        }
        fn journal(&self) -> TestResult<Journal> {
            let locations = Locations::new(&self.directory)?;
            Ok(serde_json::from_slice(&read_private(
                &locations.journal(),
                16 * 1024,
            )?)?)
        }
    }

    #[test]
    fn read_only_snapshot_captures_old_schema_without_mutating_it() -> TestResult {
        let fixture = Fixture::new()?;
        let path = fixture.directory.join("control.sqlite3");
        let before = fs::read(&path)?;
        let snapshot = Store::snapshot_existing(&path, &fixture.deployment, 4)?;
        assert_eq!(Store::existing_schema(&path, &fixture.deployment)?, 4);
        assert_eq!(fs::read(&path)?, before);
        let mut view = Connection::open_in_memory()?;
        view.deserialize_read_exact(rusqlite::MAIN_DB, snapshot.as_slice(), snapshot.len(), true)?;
        assert_eq!(
            view.pragma_query_value(None, "user_version", |row| row.get::<_, i32>(0))?,
            4
        );
        assert!(Store::snapshot_existing(&path, &fixture.deployment, SCHEMA_VERSION).is_err());
        let missing = fixture.directory.join("missing.sqlite3");
        assert!(Store::snapshot_existing(&missing, &fixture.deployment, 4).is_err());
        assert!(!missing.exists());
        Ok(())
    }

    #[test]
    fn migration_preserves_identity_epoch_and_discards_legacy_recovery_codes() -> TestResult {
        let fixture = Fixture::new()?;
        let original = fs::read(fixture.directory.join("control.sqlite3"))?;
        let receipt = fixture.migrate(false)?;
        assert_eq!(
            Store::existing_schema(
                &fixture.directory.join("control.sqlite3"),
                &fixture.deployment
            )?,
            SCHEMA_VERSION
        );
        assert_eq!(*load_key(&fixture.directory.join("vault.key"))?, [4; 32]);
        assert_eq!(*load_key(&fixture.directory.join("permit.key"))?, [5; 32]);
        let store = Store::open_existing(
            &fixture.directory.join("control.sqlite3"),
            &fixture.deployment,
        )?;
        assert_eq!(store.security_epoch()?, 17);
        let connection = Connection::open(fixture.directory.join("control.sqlite3"))?;
        assert_eq!(
            connection.query_row(
                "SELECT count(*) FROM recovery_codes WHERE consumed=0",
                [],
                |row| row.get::<_, i32>(0)
            )?,
            0
        );
        assert_eq!(
            connection.query_row(
                "SELECT count(*) FROM recovery_codes WHERE consumed=1",
                [],
                |row| row.get::<_, i32>(0)
            )?,
            0
        );
        assert_eq!(
            fs::read(
                fixture
                    .parent
                    .join(receipt.previous_directory)
                    .join("control.sqlite3")
            )?,
            original
        );
        let archive = read_private(
            &fixture.parent.join("upgrade-backup.nl15"),
            MAX_ARCHIVE_BYTES as u64,
        )?;
        let backup = DeploymentBackup::decrypt(&archive, PASSWORD, &fixture.deployment)?;
        assert_eq!(digest(&backup.database), receipt.old_snapshot_sha256);
        assert!(DeploymentLease::runtime(&fixture.directory).is_ok());
        Ok(())
    }

    #[test]
    fn runtime_and_other_operations_block_migration_with_no_backup_or_schema_write() -> TestResult {
        let fixture = Fixture::new()?;
        let operation = DeploymentLease::operation(&fixture.directory)?;
        assert!(
            matches!(fixture.migrate(false),Err(error) if error.downcast_ref::<UpgradeError>().is_some_and(|error|matches!(error,UpgradeError::Busy)))
        );
        assert!(!fixture.parent.join("upgrade-backup.nl15").exists());
        drop(operation);
        let runtime = DeploymentLease::runtime(&fixture.directory)?;
        assert!(DeploymentLease::runtime(&fixture.directory).is_err());
        assert!(fixture.migrate(false).is_err());
        drop(runtime);
        assert_eq!(
            Store::existing_schema(
                &fixture.directory.join("control.sqlite3"),
                &fixture.deployment
            )?,
            4
        );
        Ok(())
    }

    #[test]
    fn deferred_upgrade_refuses_business_then_restores_exact_original_directory() -> TestResult {
        let fixture = Fixture::new()?;
        let original = fs::read(fixture.directory.join("control.sqlite3"))?;
        let receipt = fixture.migrate(true)?;
        assert!(matches!(
            DeploymentLease::runtime(&fixture.directory),
            Err(UpgradeError::Incomplete)
        ));
        assert!(
            recover(
                &fixture.directory,
                &nestlink_auth::random_id(),
                Recovery::Rollback
            )
            .is_err()
        );
        recover(
            &fixture.directory,
            &receipt.transaction_id,
            Recovery::Rollback,
        )?;
        assert_eq!(
            Store::existing_schema(
                &fixture.directory.join("control.sqlite3"),
                &fixture.deployment
            )?,
            4
        );
        assert_eq!(
            fs::read(fixture.directory.join("control.sqlite3"))?,
            original
        );
        assert!(DeploymentLease::runtime(&fixture.directory).is_ok());
        Ok(())
    }

    #[test]
    fn crash_gap_recovers_by_exact_paths_even_when_phase_write_did_not_happen() -> TestResult {
        let fixture = Fixture::new()?;
        let receipt = fixture.migrate(true)?;
        let journal = fixture.journal()?;
        // Model power loss in the directory-rename gap. Proofs and stable
        // journal were produced by the real migration path, not a test copy.
        fs::rename(
            &fixture.directory,
            fixture.parent.join(&journal.candidate_name),
        )?;
        assert!(!fixture.directory.exists());
        assert!(DeploymentLease::runtime(&fixture.directory).is_err());
        recover(
            &fixture.directory,
            &receipt.transaction_id,
            Recovery::Complete,
        )?;
        assert_eq!(
            Store::existing_schema(
                &fixture.directory.join("control.sqlite3"),
                &fixture.deployment
            )?,
            SCHEMA_VERSION
        );
        Ok(())
    }

    #[test]
    fn admitted_state_and_reappeared_terminal_journal_cannot_resurrect_consumed_codes() -> TestResult
    {
        let fixture = Fixture::new()?;
        let receipt = fixture.migrate(true)?;
        let mut journal = fixture.journal()?;
        recover(
            &fixture.directory,
            &receipt.transaction_id,
            Recovery::Complete,
        )?;
        let connection = Connection::open(fixture.directory.join("control.sqlite3"))?;
        connection.execute("UPDATE recovery_codes SET consumed=1", [])?;
        drop(connection);
        assert!(
            recover(
                &fixture.directory,
                &receipt.transaction_id,
                Recovery::Rollback
            )
            .is_err()
        );
        journal.phase = "completed".into();
        create_private(
            &Locations::new(&fixture.directory)?.journal(),
            &serde_json::to_vec(&journal)?,
        )?;
        assert!(
            recover(
                &fixture.directory,
                &receipt.transaction_id,
                Recovery::Rollback
            )
            .is_err()
        );
        recover(
            &fixture.directory,
            &receipt.transaction_id,
            Recovery::Complete,
        )?;
        let connection = Connection::open(fixture.directory.join("control.sqlite3"))?;
        assert_eq!(
            connection.query_row(
                "SELECT count(*) FROM recovery_codes WHERE consumed=0",
                [],
                |row| row.get::<_, i32>(0)
            )?,
            0
        );
        Ok(())
    }
}
