//! SQLite's online backup API, never a raw copy of a live WAL database.
use crate::{APPLICATION_ID, SCHEMA_VERSION, StorageError, Store, require_id};
use rusqlite::{
    Connection, MAIN_DB, OpenFlags,
    backup::{Backup, StepResult},
};
use std::{
    path::Path,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;
const BUDGET: Duration = Duration::from_secs(10);

impl Store {
    /// Inspect an existing database without invoking initialize or any migration.
    pub fn existing_schema(path: &Path, deployment_id: &str) -> Result<i32, StorageError> {
        let store = readonly_existing(path, deployment_id)?;
        Ok(store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?)
    }

    /// Consistent pre-migration backup. This read-only connection never calls
    /// initialize; committed WAL is captured through SQLite's online backup.
    pub fn snapshot_existing(
        path: &Path,
        deployment_id: &str,
        expected_schema: i32,
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let store = readonly_existing(path, deployment_id)?;
        let schema: i32 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if schema != expected_schema {
            return Err(StorageError::Invalid(
                "existing database schema differs from the migration plan",
            ));
        }
        store.snapshot()
    }

    /// A consistent, bounded snapshot even while another process writes to WAL.
    pub fn snapshot(&self) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let page_size: u64 = self
            .connection
            .pragma_query_value(None, "page_size", |r| r.get(0))?;
        let page_count: u64 = self
            .connection
            .pragma_query_value(None, "page_count", |r| r.get(0))?;
        check_size(page_size, page_count)?;
        let mut destination = Connection::open_in_memory()?;
        {
            let backup = Backup::new(&self.connection, &mut destination)?;
            let started = Instant::now();
            loop {
                if started.elapsed() >= BUDGET {
                    return Err(StorageError::Invalid("snapshot exceeded time budget"));
                }
                let result = backup.step(64)?;
                let total = u64::try_from(backup.progress().pagecount)
                    .map_err(|_| StorageError::Invalid("invalid snapshot page count"))?;
                check_size(page_size, total)?;
                match result {
                    StepResult::Done => break,
                    StepResult::Busy | StepResult::Locked => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    StepResult::More => std::thread::yield_now(),
                    _ => return Err(StorageError::Invalid("unsupported snapshot result")),
                }
            }
        }
        let serialized = destination.serialize(MAIN_DB)?;
        if serialized.len() > MAX_SNAPSHOT_BYTES || serialized.len() < 100 {
            return Err(StorageError::Invalid("snapshot size invalid"));
        }
        let mut bytes = Zeroizing::new(serialized.to_vec());
        // SQLite deserialize supports rollback-journal images, not WAL images.
        // Backup has already incorporated all committed WAL pages in this image.
        bytes[18] = 1;
        bytes[19] = 1;
        Ok(bytes)
    }

    /// Called only after the containing archive has authenticated successfully.
    pub fn from_snapshot(bytes: &[u8], deployment_id: &str) -> Result<Self, StorageError> {
        require_id(deployment_id)?;
        if !(100..=MAX_SNAPSHOT_BYTES).contains(&bytes.len())
            || !bytes.starts_with(b"SQLite format 3\0")
            || bytes[18] != 1
            || bytes[19] != 1
        {
            return Err(StorageError::Invalid("invalid SQLite snapshot envelope"));
        }
        let mut connection = Connection::open_in_memory()?;
        connection.deserialize_read_exact(MAIN_DB, bytes, bytes.len(), false)?;
        // Prevent restored schema expressions from invoking extension functions.
        connection.pragma_update(None, "trusted_schema", "OFF")?;
        let app: i32 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i32 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if app != APPLICATION_ID || !(4..=SCHEMA_VERSION).contains(&version) {
            return Err(StorageError::Invalid(
                "snapshot has a foreign or unsupported namespace",
            ));
        }
        let integrity: String = connection.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if integrity != "ok" || connection.prepare("PRAGMA foreign_key_check")?.exists([])? {
            return Err(StorageError::Invalid("snapshot integrity check failed"));
        }
        Self::initialize(connection, deployment_id)
    }
}

fn readonly_existing(path: &Path, deployment_id: &str) -> Result<Store, StorageError> {
    require_id(deployment_id)?;
    let connection = crate::file_connection::open_file(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    let application: i32 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application != APPLICATION_ID || !(4..=SCHEMA_VERSION).contains(&version) {
        return Err(StorageError::Invalid(
            "existing snapshot namespace or schema is unsupported",
        ));
    }
    let actual: String =
        connection.query_row("SELECT id FROM deployment WHERE singleton=1", [], |row| {
            row.get(0)
        })?;
    if actual != deployment_id {
        return Err(StorageError::Invalid(
            "database belongs to a different deployment",
        ));
    }
    let integrity: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if integrity != "ok" || connection.prepare("PRAGMA foreign_key_check")?.exists([])? {
        return Err(StorageError::Invalid(
            "existing snapshot integrity check failed",
        ));
    }
    Ok(Store {
        connection,
        internal_software_media_candidate: None,
        #[cfg(test)]
        media_regression_requests: std::collections::BTreeSet::new(),
    })
}

fn check_size(page_size: u64, pages: u64) -> Result<(), StorageError> {
    if !(512..=65_536).contains(&page_size)
        || !page_size.is_power_of_two()
        || page_size
            .checked_mul(pages)
            .is_none_or(|n| n > MAX_SNAPSHOT_BYTES as u64)
    {
        return Err(StorageError::Invalid("snapshot exceeds size budget"));
    }
    Ok(())
}
