use super::*;
use nestlink_protocol::file_recovery::DownloadRecoveryScope;
use std::fs;

fn id(number: u8) -> String {
    format!("00000000-0000-4000-8000-{number:012x}")
}
fn facts(bytes: &[u8]) -> DownloadRecoveryFacts {
    DownloadRecoveryFacts {
        scope: DownloadRecoveryScope {
            deployment_id: id(1),
            security_epoch: 1,
            account_id: id(2),
            controller_device_id: id(3),
            host_device_id: id(4),
            controller_key_sha256: [1; 32],
            host_key_sha256: [2; 32],
            resource_id: id(5),
        },
        root_id: id(6),
        relative_path: "source".into(),
        size: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    }
}
fn staged(
    store: &DownloadRecoveryStore,
    area: &Path,
    number: u8,
    bytes: &[u8],
    checkpoint: usize,
) -> io::Result<Record> {
    create_fresh_area(area)?;
    let directory = open_directory(area)?;
    let temporary = format!(".nestlink-{}.part", id(number).replace('-', ""));
    let mut create = options(true);
    create.create_new(true);
    let mut file = directory.open_with(&temporary, &create)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let record = Record {
        task_id: id(number),
        facts: facts(bytes),
        area: area.into(),
        temporary,
        name: "done".into(),
        directory: Some(ObjectId::from(&directory.dir_metadata()?)),
        file: Some(ObjectId::from(&file.metadata()?)),
        checkpoint: checkpoint as u64,
        prefix_sha256: Sha256::digest(&bytes[..checkpoint]).into(),
        stage: Stage::Staged,
        temporary_removed: false,
        file_synced: true,
        directory_synced: sync_directory(&directory)?,
        operation_error: None,
        cleanup_error: None,
        last_export: None,
    };
    store.change(|ledger| {
        ledger
            .records
            .insert(record.task_id.clone(), record.clone());
        Ok(())
    })?;
    Ok(record)
}
fn manifest(record: &Record) -> FileReadManifest {
    FileReadManifest {
        size: record.facts.size,
        sha256: record.facts.sha256.to_vec(),
        offset: record.checkpoint,
    }
}
fn state_directory(parent: &Path) -> io::Result<PathBuf> {
    let state = parent.join("state");
    nestlink_platform_security::new_private_directory(&state)?;
    Ok(state)
}

#[test]
fn stable_singleton_and_established_missing_ledger_fail_closed() -> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 100, 4)?;
    assert_eq!(
        DownloadRecoveryStore::open(&state, 100, 4)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    assert_eq!(store.list()?.1, 0);
    drop(store);
    fs::remove_file(state.join(LEDGER))?;
    assert_eq!(
        DownloadRecoveryStore::open(&state, 100, 4)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    Ok(())
}

#[test]
fn restart_keeps_reservation_and_waiting_facts_without_a_live_owner_or_consent() -> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 16, 4)?;
    let record = staged(&store, &temporary.path().join("area"), 10, b"abcdefgh", 3)?;
    store.claim(&record.task_id)?;
    assert!(store.list()?.0[0].owner_active);
    drop(store);
    let store = DownloadRecoveryStore::open(&state, 16, 4)?;
    let (tasks, reserved) = store.list()?;
    assert_eq!(reserved, 8);
    assert_eq!(tasks[0].phase, "waiting_for_approval");
    assert!(!tasks[0].owner_active && !tasks[0].published);
    assert_eq!(tasks[0].checkpoint_bytes, 3);
    assert_eq!(fs::read(record.area.join(&record.temporary))?, b"abcdefgh");
    let raw = fs::read_to_string(state.join(LEDGER))?;
    for forbidden in [
        "permit",
        "session_id",
        "connection_generation",
        "proof",
        "password",
        "consent",
        "granted_permissions",
    ] {
        assert!(
            !raw.contains(forbidden),
            "old authority must not be serialized: {forbidden}"
        );
    }
    Ok(())
}

#[test]
fn uncheckpointed_tail_is_truncated_only_after_exact_prefix_proof_and_seeds_verifier()
-> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 100, 4)?;
    let record = staged(&store, &temporary.path().join("area"), 10, b"abcdefgh", 3)?;
    let (directory, file, mut verifier, hash) =
        reopen_checkpoint(&record, &manifest(&record), &mut || Ok(()))?;
    assert_eq!(file.metadata()?.len(), 3);
    assert_eq!(hash.finalize().as_slice(), record.prefix_sha256.as_slice());
    verifier.accept(&FileReadChunk {
        offset: 3,
        data: b"defgh".to_vec(),
        sha256: Sha256::digest(b"defgh").to_vec(),
    })?;
    verifier.finish()?;
    drop(file);
    assert_eq!(directory.read(&record.temporary)?, b"abc");
    assert_eq!(store.list()?.0[0].checkpoint_bytes, 3);
    Ok(())
}

#[test]
fn modified_prefix_and_revoked_reopen_never_truncate_or_confirm_the_tail() -> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 100, 4)?;
    let record = staged(&store, &temporary.path().join("area"), 10, b"abcdefgh", 3)?;
    fs::write(record.area.join(&record.temporary), b"Xbcdefgh")?;
    assert!(reopen_checkpoint(&record, &manifest(&record), &mut || Ok(())).is_err());
    assert_eq!(fs::read(record.area.join(&record.temporary))?, b"Xbcdefgh");
    fs::write(record.area.join(&record.temporary), b"abcdefgh")?;
    assert_eq!(
        reopen_checkpoint(&record, &manifest(&record), &mut || Err(denied(
            "new approval revoked"
        )))
        .err()
        .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(fs::read(record.area.join(&record.temporary))?, b"abcdefgh");
    Ok(())
}

#[test]
fn replacement_or_extra_link_is_rejected_and_cleanup_never_touches_the_replacement()
-> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 100, 4)?;
    let record = staged(&store, &temporary.path().join("area"), 10, b"abcdefgh", 3)?;
    let original = record.area.join(&record.temporary);
    let unrelated = temporary.path().join("unrelated");
    fs::hard_link(&original, &unrelated)?;
    assert!(reopen_checkpoint(&record, &manifest(&record), &mut || Ok(())).is_err());
    assert!(store.cancel(&record.task_id).is_err());
    assert_eq!(fs::read(&unrelated)?, b"abcdefgh");
    fs::remove_file(&unrelated)?;
    fs::rename(&original, &unrelated)?;
    fs::write(&original, b"replacement")?;
    assert!(store.cancel(&record.task_id).is_err());
    assert_eq!(fs::read(&original)?, b"replacement");
    assert_eq!(fs::read(&unrelated)?, b"abcdefgh");
    assert_eq!(store.list()?.1, 8);
    Ok(())
}

#[cfg(unix)]
#[test]
fn directory_and_file_symlinks_are_not_recovery_authority() -> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 100, 4)?;
    let record = staged(&store, &temporary.path().join("area"), 10, b"abcdefgh", 3)?;
    let moved = temporary.path().join("original-area");
    fs::rename(&record.area, &moved)?;
    std::os::unix::fs::symlink(&moved, &record.area)?;
    assert!(reopen_checkpoint(&record, &manifest(&record), &mut || Ok(())).is_err());
    assert!(store.cancel(&record.task_id).is_err());
    assert_eq!(fs::read(moved.join(&record.temporary))?, b"abcdefgh");
    Ok(())
}

#[test]
fn pending_newer_checkpoint_is_not_promoted_on_restart() -> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 100, 4)?;
    let record = staged(&store, &temporary.path().join("area"), 10, b"abcdefgh", 3)?;
    let mut pending = lock(&store.state).ledger.clone();
    pending.sequence += 1;
    let item = pending
        .records
        .get_mut(&record.task_id)
        .ok_or_else(|| invalid("missing fixture record"))?;
    item.checkpoint = 8;
    item.prefix_sha256 = item.facts.sha256;
    nestlink_platform_security::create_private(&state.join(PENDING), &encode(&pending)?)?;
    drop(store);
    let store = DownloadRecoveryStore::open(&state, 100, 4)?;
    assert!(!state.join(PENDING).exists());
    assert_eq!(store.resume_facts(&record.task_id)?.checkpoint_bytes, 3);
    assert_eq!(fs::read(record.area.join(&record.temporary))?, b"abcdefgh");
    Ok(())
}

#[test]
fn invalid_pending_and_changed_limits_do_not_reset_reservations() -> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 100, 4)?;
    let record = staged(&store, &temporary.path().join("area"), 10, b"abcdefgh", 3)?;
    nestlink_platform_security::create_private(&state.join(PENDING), b"invalid")?;
    drop(store);
    assert!(DownloadRecoveryStore::open(&state, 100, 4).is_err());
    assert!(state.join(PENDING).exists());
    fs::remove_file(state.join(PENDING))?;
    assert!(DownloadRecoveryStore::open(&state, 101, 4).is_err());
    let store = DownloadRecoveryStore::open(&state, 100, 4)?;
    assert_eq!(store.list()?.1, record.facts.size);
    Ok(())
}

#[test]
fn aggregate_reserved_bytes_and_record_count_survive_restart_and_failed_cleanup() -> io::Result<()>
{
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 8, 2)?;
    let record = staged(&store, &temporary.path().join("area"), 10, b"abcdefgh", 3)?;
    drop(store);
    let store = DownloadRecoveryStore::open(&state, 8, 2)?;
    let mut extra = record.clone();
    extra.task_id = id(11);
    extra.temporary = format!(".nestlink-{}.part", id(11).replace('-', ""));
    assert!(
        store
            .change(|ledger| {
                ledger.records.insert(extra.task_id.clone(), extra);
                Ok(())
            })
            .is_err()
    );
    assert_eq!(store.list()?.0.len(), 1);
    fs::rename(&record.area, temporary.path().join("unavailable"))?;
    assert!(store.cancel(&record.task_id).is_err());
    assert_eq!(store.list()?.1, 8);
    assert!(store.list()?.0[0].cleanup_error.is_some());
    Ok(())
}

#[test]
fn publication_gap_reconciles_both_link_states_without_deleting_the_final() -> io::Result<()> {
    for temporary_removed in [false, true] {
        let temporary = tempfile::tempdir()?;
        let state = state_directory(temporary.path())?;
        let store = DownloadRecoveryStore::open(&state, 100, 4)?;
        let mut record = staged(&store, &temporary.path().join("area"), 10, b"complete", 8)?;
        record.stage = Stage::Publishing;
        store.update(&record.task_id, |item| {
            item.stage = Stage::Publishing;
            Ok(())
        })?;
        fs::hard_link(
            record.area.join(&record.temporary),
            record.area.join(&record.name),
        )?;
        if temporary_removed {
            fs::remove_file(record.area.join(&record.temporary))?;
        }
        drop(store);
        let store = DownloadRecoveryStore::open(&state, 100, 4)?;
        store.cancel(&record.task_id)?;
        assert_eq!(fs::read(record.area.join(&record.name))?, b"complete");
        assert!(!record.area.join(&record.temporary).exists());
        assert!(store.list()?.0[0].published && store.list()?.0[0].temporary_removed);
        assert_eq!(store.list()?.1, 0);
    }
    Ok(())
}

#[test]
fn partial_export_copies_only_the_checkpoint_and_retains_original_reservation() -> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 100, 4)?;
    let record = staged(&store, &temporary.path().join("area"), 10, b"abcdefgh", 3)?;
    let export = temporary.path().join("export");
    store.export_partial(&record.task_id, &export, "saved.partial")?;
    assert_eq!(fs::read(export.join("saved.partial"))?, b"abc");
    assert_eq!(fs::read(record.area.join(&record.temporary))?, b"abcdefgh");
    assert_eq!(store.list()?.1, 8);
    assert!(
        store.list()?.0[0]
            .last_export
            .as_ref()
            .is_some_and(|value| value.contains("published_partial; staging_removed"))
    );
    assert!(
        store
            .export_partial(
                &record.task_id,
                &temporary.path().join("second-export"),
                "other.partial"
            )
            .is_err()
    );
    assert!(!temporary.path().join("second-export").exists());
    store.cancel(&record.task_id)?;
    assert_eq!(store.list()?.1, 0);
    assert_eq!(fs::read(export.join("saved.partial"))?, b"abc");
    Ok(())
}

#[test]
fn reapproved_host_root_reuses_only_directory_identity_and_never_stores_consent() -> io::Result<()>
{
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 100, 4)?;
    let folder = temporary.path().join("host-root");
    fs::create_dir(&folder)?;
    assert_eq!(store.approved_read_root_id(&folder, &id(10))?, id(10));
    drop(store);
    let store = DownloadRecoveryStore::open(&state, 100, 4)?;
    assert_eq!(store.approved_read_root_id(&folder, &id(11))?, id(10));
    assert!(store.list()?.0.is_empty());
    assert_eq!(store.list()?.1, 0);
    Ok(())
}

#[test]
fn task_capacity_is_independent_of_available_byte_budget_and_survives_restart() -> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 100, 1)?;
    let record = staged(&store, &temporary.path().join("area"), 10, b"abcdefgh", 3)?;
    drop(store);
    let store = DownloadRecoveryStore::open(&state, 100, 1)?;
    let mut extra = record.clone();
    extra.task_id = id(11);
    extra.temporary = format!(".nestlink-{}.part", id(11).replace('-', ""));
    assert!(
        store
            .change(|ledger| {
                ledger.records.insert(extra.task_id.clone(), extra);
                Ok(())
            })
            .is_err()
    );
    assert_eq!(store.list()?.0.len(), 1);
    assert_eq!(store.list()?.1, 8);
    assert_eq!(fs::read(record.area.join(record.temporary))?, b"abcdefgh");
    Ok(())
}

#[test]
fn export_reserves_its_second_copy_before_creating_any_destination() -> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 8, 2)?;
    let record = staged(&store, &temporary.path().join("area"), 10, b"abcdefgh", 3)?;
    let export = temporary.path().join("export");
    assert!(
        store
            .export_partial(&record.task_id, &export, "saved.partial")
            .is_err()
    );
    assert!(!export.exists());
    assert!(store.list()?.0[0].last_export.is_none());
    assert_eq!(store.list()?.1, 8);
    Ok(())
}

// A private filesystem crash fixture, deliberately not a fabricated source
// snapshot or permit. The real SDK killed-process tests cover fresh authority.
fn interrupted_export(
    store: &DownloadRecoveryStore,
    record: &Record,
    area: &Path,
) -> io::Result<PartialExport> {
    create_fresh_area(area)?;
    let directory = open_directory(area)?;
    let mut create = options(true);
    create.create_new(true);
    let mut file = directory.open_with(EXPORT_TEMPORARY, &create)?;
    file.write_all(b"abc")?;
    file.sync_all()?;
    let export = PartialExport {
        area: area.into(),
        name: "saved.partial".into(),
        directory: Some(ObjectId::from(&directory.dir_metadata()?)),
        file: Some(ObjectId::from(&file.metadata()?)),
        checkpoint: 3,
        sha256: Sha256::digest(b"abc").into(),
        published: false,
        temporary_removed: false,
        file_synced: true,
        directory_synced: false,
        error: None,
    };
    store.update(&record.task_id, |item| {
        item.last_export = Some(export.clone());
        Ok(())
    })?;
    Ok(export)
}

#[test]
fn restart_retains_export_budget_and_reconciles_both_partial_publication_gaps() -> io::Result<()> {
    for removed in [false, true] {
        let temporary = tempfile::tempdir()?;
        let state = state_directory(temporary.path())?;
        let store = DownloadRecoveryStore::open(&state, 11, 2)?;
        let record = staged(&store, &temporary.path().join("area"), 10, b"abcdefgh", 3)?;
        let export = interrupted_export(&store, &record, &temporary.path().join("export"))?;
        fs::hard_link(
            export.area.join(EXPORT_TEMPORARY),
            export.area.join(&export.name),
        )?;
        if removed {
            fs::remove_file(export.area.join(EXPORT_TEMPORARY))?;
        }
        drop(store);
        let store = DownloadRecoveryStore::open(&state, 11, 2)?;
        assert_eq!(store.list()?.1, 11);
        store.cancel(&record.task_id)?;
        assert_eq!(store.list()?.1, 0);
        assert_eq!(fs::read(export.area.join(&export.name))?, b"abc");
        assert!(!export.area.join(EXPORT_TEMPORARY).exists());
        assert!(
            store.list()?.0[0]
                .last_export
                .as_ref()
                .is_some_and(|value| value.contains("published_partial; staging_removed"))
        );
    }
    Ok(())
}

#[test]
fn replaced_export_staging_is_retained_and_charged_even_after_original_partial_cleanup()
-> io::Result<()> {
    let temporary = tempfile::tempdir()?;
    let state = state_directory(temporary.path())?;
    let store = DownloadRecoveryStore::open(&state, 11, 2)?;
    let record = staged(&store, &temporary.path().join("area"), 10, b"abcdefgh", 3)?;
    let export = interrupted_export(&store, &record, &temporary.path().join("export"))?;
    let unrelated = temporary.path().join("retained-original");
    fs::rename(export.area.join(EXPORT_TEMPORARY), &unrelated)?;
    fs::write(export.area.join(EXPORT_TEMPORARY), b"replacement")?;
    assert!(store.cancel(&record.task_id).is_err());
    assert!(store.list()?.0[0].temporary_removed);
    assert_eq!(store.list()?.1, 3);
    assert_eq!(
        fs::read(export.area.join(EXPORT_TEMPORARY))?,
        b"replacement"
    );
    assert_eq!(fs::read(&unrelated)?, b"abc");
    drop(store);
    let store = DownloadRecoveryStore::open(&state, 11, 2)?;
    assert_eq!(store.list()?.1, 3);
    assert!(
        store.list()?.0[0]
            .last_export
            .as_ref()
            .is_some_and(|value| value.contains("cleanup_pending"))
    );
    Ok(())
}
