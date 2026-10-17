use super::*;
use nestlink_platform_files::upload::{
    LocalUploadSelection, WriteQuota, WriteRootConsent, WriteRootSelection, WriteRoots,
};
use nestlink_protocol::{
    FILE_WRITE_ACTIVE, FILE_WRITE_TRANSFERS, FileWriteChunk, FileWriteErrorCode, FileWriteOpen,
    FileWriteState, NativeFileWrite, native_file_write::Action as WriteAction,
};
use nestlink_remote::upload::{
    FileUploadSourceFactory, FileWriteClient, FileWriteConsent, FileWriteDestination,
    FileWriteDevice, FileWriteError, FileWriteMonitor, FileWriteServer,
};

fn writable(
    area: &FsPath,
    maximum: u64,
    quota: u64,
) -> Result<(String, WriteRoots, WriteRootConsent)> {
    let id = random_id();
    let (selection, consent) = WriteRootSelection::new(&id, area, maximum, quota)?;
    Ok((id, WriteRoots::new(vec![selection])?, consent))
}
fn chunk(offset: u64, bytes: &[u8]) -> FileWriteChunk {
    FileWriteChunk {
        offset,
        data: bytes.into(),
        sha256: digest(bytes).to_vec(),
    }
}
fn code(error: FileWriteError) -> Result<FileWriteErrorCode> {
    if let FileWriteError::Destination(failure) = error {
        Ok(FileWriteErrorCode::try_from(failure.code)?)
    } else {
        Err(format!("expected destination failure, got {error:?}").into())
    }
}
async fn written(
    monitor: &FileWriteMonitor,
    id: &str,
    predicate: impl Fn(&FileWriteState) -> bool,
) -> Result<FileWriteState> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(state) = monitor.status().transfers.get(id)
                && predicate(state)
            {
                return Ok(*state);
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?
}
async fn write_finished(monitor: &FileWriteMonitor) -> Result {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !monitor.status().finished {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?;
    Ok(())
}
fn no_partial(area: &FsPath) -> Result {
    if area.exists() {
        assert!(fs::read_dir(area)?.all(|entry| entry.is_ok_and(|entry| {
            !entry
                .file_name()
                .to_string_lossy()
                .starts_with(".nestlink-upload-")
        })));
    }
    Ok(())
}

#[tokio::test]
async fn complete_owned_uploads_publish_actual_tls_quic_and_empty_files() -> Result {
    for quic in [false, true] {
        for empty in [false, true] {
            let temporary = tempfile::tempdir()?;
            let area = temporary.path().join("received");
            let local_source = temporary.path().join("selected-source");
            let bytes: Vec<_> = (0..if empty { 0 } else { 3 * 61440 + 37 })
                .map(|i| (i % 251) as u8)
                .collect();
            fs::write(&local_source, &bytes)?;
            let (root, roots, _keep_write) = writable(&area, FILE_SIZE_BYTES, FILE_SIZE_BYTES)?;
            let (selected, _keep_source) =
                LocalUploadSelection::new(&local_source, FILE_SIZE_BYTES)?;
            let mut sessions =
                Sessions::new(quic, vec![Permission::View, Permission::FileWrite]).await?;
            let mut server = FileWriteServer::start(&mut sessions.h, 9, roots)?;
            let monitor = server.monitor();
            let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
            let id = random_id();
            let receipt = client.upload_source(&id, &root, "done", selected).await?;
            let state = receipt
                .state
                .ok_or("complete upload omitted actual publication facts")?;
            assert_eq!(receipt.sha256, digest(&bytes));
            assert_eq!(state.confirmed_bytes, bytes.len() as u64);
            assert!(
                state.published && state.file_closed && state.temporary_removed && !state.poisoned
            );
            #[cfg(unix)]
            assert!(state.directory_synced);
            #[cfg(windows)]
            assert!(!state.directory_synced);
            let source = client
                .source_monitor()
                .ok_or("owned source monitor missing")?
                .status();
            assert!(source.finished && source.source_verified && source.source_closed);
            assert_eq!(source.error, None);
            assert_eq!(source.read_bytes, bytes.len() as u64);
            assert_eq!(fs::read(area.join("done"))?, bytes);
            assert_eq!(monitor.status().transfers.get(&id), Some(&state));
            no_partial(&area)?;
            client.retire()?;
            sessions
                .c
                .send(Channel::Video, b"viewing survives file upload retirement")
                .await?;
            assert_eq!(
                sessions.h.receive().await?.payload,
                b"viewing survives file upload retirement"
            );
            assert_eq!(
                server.shutdown(StopReason::ExplicitExit).await?,
                FileShutdown::Finished
            );
            sessions.c.shutdown(StopReason::ExplicitExit).await?;
            sessions.h.shutdown(StopReason::ExplicitExit).await?;
            write_finished(&monitor).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn file_read_permission_does_not_authorize_the_write_channel() -> Result {
    let temporary = tempfile::tempdir()?;
    let area = temporary.path().join("not-created");
    let (_, roots, _keep) = writable(&area, 4, 4)?;
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    assert!(FileWriteServer::start(&mut sessions.h, 9, roots).is_err());
    assert!(FileWriteClient::attach(&mut sessions.c, 9).is_err());
    assert!(!area.exists());
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn cancellation_and_independent_root_revocation_clean_real_partial_files() -> Result {
    for revoked in [false, true] {
        let temporary = tempfile::tempdir()?;
        let area = temporary.path().join("received");
        let (root, roots, consent) = writable(&area, 4, 4)?;
        let mut sessions =
            Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
        let mut server = FileWriteServer::start(&mut sessions.h, 9, roots)?;
        let monitor = server.monitor();
        let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
        let id = random_id();
        let mut upload = client.open(&id, &root, "done", 4, digest(b"data")).await?;
        client.write_chunk(&mut upload, chunk(0, b"da")).await?;
        if revoked {
            consent.revoke();
            written(&monitor, &id, |state| {
                state.file_closed && state.temporary_removed
            })
            .await?;
            assert_eq!(
                code(
                    client
                        .write_chunk(&mut upload, chunk(2, b"ta"))
                        .await
                        .err()
                        .ok_or("revoked destination accepted bytes")?
                )?,
                FileWriteErrorCode::FileWriteDenied
            );
        } else {
            let cancelled = client.cancel(&mut upload).await?;
            assert!(cancelled.file_closed && cancelled.temporary_removed && !cancelled.published);
        }
        assert_eq!(upload.offset(), 2);
        assert!(upload.finished());
        assert!(!area.join("done").exists());
        no_partial(&area)?;
        client.retire()?;
        sessions.c.send(Channel::Video, b"still viewing").await?;
        assert_eq!(sessions.h.receive().await?.payload, b"still viewing");
        server.shutdown(StopReason::ExplicitExit).await?;
        sessions.c.shutdown(StopReason::ExplicitExit).await?;
        sessions.h.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}

#[tokio::test]
async fn complete_checksum_mismatch_removes_staging_without_publication() -> Result {
    let temporary = tempfile::tempdir()?;
    let area = temporary.path().join("received");
    let (root, roots, _keep) = writable(&area, 4, 4)?;
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
    let mut server = FileWriteServer::start(&mut sessions.h, 9, roots)?;
    let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
    let mut upload = client
        .open(&random_id(), &root, "done", 4, digest(b"other bytes"))
        .await?;
    client.write_chunk(&mut upload, chunk(0, b"data")).await?;
    assert_eq!(
        code(
            client
                .commit(&mut upload)
                .await
                .err()
                .ok_or("wrong full digest committed")?
        )?,
        FileWriteErrorCode::FileWriteChecksumMismatch
    );
    let actual = upload
        .destination_state()
        .ok_or("checksum failure lost actual cleanup facts")?;
    assert!(!actual.published && actual.file_closed && actual.temporary_removed);
    assert!(!area.join("done").exists());
    no_partial(&area)?;
    client.retire()?;
    server.shutdown(StopReason::ExplicitExit).await?;
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn publication_races_never_replace_existing_files_directories_or_links() -> Result {
    for kind in ["file", "directory", "hardlink", "symlink"] {
        #[cfg(windows)]
        if kind == "symlink" {
            continue;
        } // Windows junction parent test below exercises reparse traversal.
        let temporary = tempfile::tempdir()?;
        let area = temporary.path().join("received");
        let (root, roots, _keep) = writable(&area, 4, 4)?;
        let mut sessions =
            Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
        let mut server = FileWriteServer::start(&mut sessions.h, 9, roots)?;
        let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
        let mut upload = client
            .open(&random_id(), &root, "done", 4, digest(b"data"))
            .await?;
        client.write_chunk(&mut upload, chunk(0, b"data")).await?;
        match kind {
            "file" => fs::write(area.join("done"), b"untouched")?,
            "directory" => fs::create_dir(area.join("done"))?,
            "hardlink" => {
                fs::write(temporary.path().join("outside"), b"untouched")?;
                fs::hard_link(temporary.path().join("outside"), area.join("done"))?;
            }
            "symlink" => {
                #[cfg(unix)]
                std::os::unix::fs::symlink(temporary.path().join("outside"), area.join("done"))?;
            }
            _ => unreachable!(),
        }
        assert_eq!(
            code(
                client
                    .commit(&mut upload)
                    .await
                    .err()
                    .ok_or("existing target was overwritten")?
            )?,
            FileWriteErrorCode::FileWriteExists
        );
        assert!(
            !upload
                .destination_state()
                .ok_or("race cleanup state missing")?
                .published
        );
        match kind {
            "file" | "hardlink" => assert_eq!(fs::read(area.join("done"))?, b"untouched"),
            "directory" => assert!(area.join("done").is_dir()),
            "symlink" => assert!(fs::symlink_metadata(area.join("done"))?.is_symlink()),
            _ => unreachable!(),
        }
        no_partial(&area)?;
        client.retire()?;
        server.shutdown(StopReason::ExplicitExit).await?;
        sessions.c.shutdown(StopReason::ExplicitExit).await?;
        sessions.h.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}

#[tokio::test]
async fn declared_active_quota_is_released_only_when_cancelled_and_published_bytes_remain_charged()
-> Result {
    let temporary = tempfile::tempdir()?;
    let area = temporary.path().join("received");
    let (root, roots, _keep) = writable(&area, 4, 4)?;
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
    let mut server = FileWriteServer::start(&mut sessions.h, 9, roots)?;
    let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
    let mut active = client
        .open(&random_id(), &root, "first", 4, digest(b"data"))
        .await?;
    assert_eq!(
        code(
            client
                .open(&random_id(), &root, "second", 1, digest(b"x"))
                .await
                .err()
                .ok_or("active quota ignored")?
        )?,
        FileWriteErrorCode::FileWriteCapacity
    );
    client.cancel(&mut active).await?;
    let mut success = client
        .open(&random_id(), &root, "second", 4, digest(b"data"))
        .await?;
    client.write_chunk(&mut success, chunk(0, b"data")).await?;
    client.commit(&mut success).await?;
    assert_eq!(
        code(
            client
                .open(&random_id(), &root, "third", 1, digest(b"x"))
                .await
                .err()
                .ok_or("published bytes escaped quota")?
        )?,
        FileWriteErrorCode::FileWriteCapacity
    );
    assert_eq!(fs::read(area.join("second"))?, b"data");
    no_partial(&area)?;
    client.retire()?;
    server.shutdown(StopReason::ExplicitExit).await?;
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn shared_byte_quota_spans_sessions_and_published_files_remain_charged() -> Result {
    let temporary = tempfile::tempdir()?;
    let quota = Arc::new(WriteQuota::new(4, 2));
    let area_one = temporary.path().join("receiving-one");
    let area_two = temporary.path().join("receiving-two");
    let (selection_one, _consent_one) =
        WriteRootSelection::new_with_quota(&random_id(), &area_one, 4, quota.clone())?;
    let root_one = selection_one.id().to_owned();
    let (selection_two, _consent_two) =
        WriteRootSelection::new_with_quota(&random_id(), &area_two, 4, quota)?;
    let root_two = selection_two.id().to_owned();
    let roots_one = WriteRoots::new(vec![selection_one])?;
    let roots_two = WriteRoots::new(vec![selection_two])?;
    let permissions = vec![Permission::View, Permission::FileWrite];
    let mut sessions_one = Sessions::new(false, permissions.clone()).await?;
    let mut sessions_two = Sessions::new(false, permissions).await?;
    let mut server_one = FileWriteServer::start(&mut sessions_one.h, 9, roots_one)?;
    let mut server_two = FileWriteServer::start(&mut sessions_two.h, 9, roots_two)?;
    let mut client_one = FileWriteClient::attach(&mut sessions_one.c, 9)?;
    let mut client_two = FileWriteClient::attach(&mut sessions_two.c, 9)?;

    let mut active = client_one
        .open(&random_id(), &root_one, "active", 4, digest(b"data"))
        .await?;
    assert_eq!(
        code(
            client_two
                .open(&random_id(), &root_two, "too-large", 1, digest(b"x"))
                .await
                .err()
                .ok_or("a second session exceeded the shared active byte quota")?
        )?,
        FileWriteErrorCode::FileWriteCapacity
    );
    client_one.cancel(&mut active).await?;

    let mut published = client_two
        .open(&random_id(), &root_two, "published", 4, digest(b"data"))
        .await?;
    client_two
        .write_chunk(&mut published, chunk(0, b"data"))
        .await?;
    client_two.commit(&mut published).await?;
    assert_eq!(fs::read(area_two.join("published"))?, b"data");
    assert_eq!(
        code(
            client_one
                .open(
                    &random_id(),
                    &root_one,
                    "over-published-limit",
                    1,
                    digest(b"x")
                )
                .await
                .err()
                .ok_or("published bytes were released from the shared quota")?
        )?,
        FileWriteErrorCode::FileWriteCapacity
    );

    client_one.retire()?;
    client_two.retire()?;
    server_one.shutdown(StopReason::ExplicitExit).await?;
    server_two.shutdown(StopReason::ExplicitExit).await?;
    sessions_one.c.shutdown(StopReason::ExplicitExit).await?;
    sessions_one.h.shutdown(StopReason::ExplicitExit).await?;
    sessions_two.c.shutdown(StopReason::ExplicitExit).await?;
    sessions_two.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[test]
fn zero_byte_uploads_reserve_artifact_slots_until_confirmed_cleanup_or_publication() -> Result {
    let temporary = tempfile::tempdir()?;
    let quota = Arc::new(WriteQuota::new(0, 1));
    let area_one = temporary.path().join("first");
    let area_two = temporary.path().join("second");
    let area_three = temporary.path().join("third");
    let (selection_one, _consent_one) =
        WriteRootSelection::new_with_quota(&random_id(), &area_one, 0, quota.clone())?;
    let (selection_two, _consent_two) =
        WriteRootSelection::new_with_quota(&random_id(), &area_two, 0, quota.clone())?;
    let (selection_three, _consent_three) =
        WriteRootSelection::new_with_quota(&random_id(), &area_three, 0, quota)?;
    let root_one = selection_one.id().to_owned();
    let root_two = selection_two.id().to_owned();
    let root_three = selection_three.id().to_owned();
    let mut roots_one = WriteRoots::new(vec![selection_one])?;
    let mut roots_two = WriteRoots::new(vec![selection_two])?;
    let mut roots_three = WriteRoots::new(vec![selection_three])?;
    let open = |root_id: &str, path: &str| FileWriteOpen {
        root_id: root_id.into(),
        path: path.into(),
        size: 0,
        sha256: digest(b"").to_vec(),
    };
    let mut cancelled = roots_one.build(&open(&root_one, "cancelled"), &mut || Ok(()))?;
    cancelled.prepare(&mut || Ok(()))?;
    let error = roots_two
        .build(&open(&root_two, "blocked"), &mut || Ok(()))
        .err()
        .ok_or("zero-byte artifact did not reserve a shared slot")?;
    assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    cancelled.cleanup()?;

    let mut published = roots_two.build(&open(&root_two, "empty"), &mut || Ok(()))?;
    published.prepare(&mut || Ok(()))?;
    published.finish(&mut || Ok(()))?;
    assert!(published.status().published);
    let error = roots_three
        .build(&open(&root_three, "blocked-after-publish"), &mut || Ok(()))
        .err()
        .ok_or("published zero-byte artifact released its shared slot")?;
    assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    assert_eq!(fs::metadata(area_two.join("empty"))?.len(), 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn real_directory_blocking_unlink_keeps_quota_until_cleanup_retry_removes_staging() -> Result {
    let temporary = tempfile::tempdir()?;
    let quota = Arc::new(WriteQuota::new(4, 1));
    let area_one = temporary.path().join("receiving-one");
    let area_two = temporary.path().join("receiving-two");
    let (selection_one, _consent_one) =
        WriteRootSelection::new_with_quota(&random_id(), &area_one, 4, quota.clone())?;
    let (selection_two, _consent_two) =
        WriteRootSelection::new_with_quota(&random_id(), &area_two, 4, quota)?;
    let root_one = selection_one.id().to_owned();
    let root_two = selection_two.id().to_owned();
    let mut roots_one = WriteRoots::new(vec![selection_one])?;
    let mut roots_two = WriteRoots::new(vec![selection_two])?;
    let open = |root_id: &str, path: &str| FileWriteOpen {
        root_id: root_id.into(),
        path: path.into(),
        size: 4,
        sha256: digest(b"data").to_vec(),
    };
    let mut destination = roots_one.build(&open(&root_one, "first"), &mut || Ok(()))?;
    destination.prepare(&mut || Ok(()))?;
    let staged = fs::read_dir(&area_one)?
        .next()
        .ok_or("staging file was not created")??
        .path();
    let held = area_one.join(".held-for-cleanup-retry");
    fs::rename(&staged, &held)?;
    fs::create_dir(&staged)?;

    assert!(destination.cleanup().is_err());
    let state = destination.status();
    assert!(state.file_closed && !state.temporary_removed && !state.published);
    let error = roots_two
        .build(&open(&root_two, "blocked"), &mut || Ok(()))
        .err()
        .ok_or("failed real unlink released its shared reservation")?;
    assert_eq!(error.kind(), io::ErrorKind::StorageFull);

    fs::remove_dir(&staged)?;
    fs::rename(&held, &staged)?;
    destination.cleanup()?;
    assert!(destination.status().temporary_removed);
    let mut retry = roots_two.build(&open(&root_two, "retry"), &mut || Ok(()))?;
    retry.prepare(&mut || Ok(()))?;
    retry.cleanup()?;
    assert!(retry.status().file_closed && retry.status().temporary_removed);
    no_partial(&area_one)?;
    no_partial(&area_two)?;
    Ok(())
}

async fn wire(sessions: &mut Sessions, message: &NativeFileWrite) -> Result<NativeFileWrite> {
    sessions
        .c
        .send(Channel::FileWrite, &message.encode_validated()?)
        .await?;
    let frame = sessions.c.receive().await?;
    assert_eq!(frame.channel, Channel::FileWrite);
    Ok(NativeFileWrite::decode_validated(&frame.payload)?)
}
fn request(sequence: u64, id: &str, action: WriteAction) -> NativeFileWrite {
    NativeFileWrite {
        schema_version: SCHEMA_VERSION,
        connection_generation: 9,
        sequence,
        transfer_id: id.into(),
        action: Some(action),
    }
}
#[tokio::test]
async fn exact_upload_retries_do_not_write_twice_and_changed_retries_stop_the_session() -> Result {
    let temporary = tempfile::tempdir()?;
    let area = temporary.path().join("received");
    let (root, roots, _keep) = writable(&area, 4, 4)?;
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
    let mut server = FileWriteServer::start(&mut sessions.h, 9, roots)?;
    let id = random_id();
    let open = request(
        1,
        &id,
        WriteAction::Open(FileWriteOpen {
            root_id: root,
            path: "done".into(),
            size: 4,
            sha256: digest(b"data").to_vec(),
        }),
    );
    let ready = wire(&mut sessions, &open).await?;
    assert_eq!(wire(&mut sessions, &open).await?, ready);
    let first = request(2, &id, WriteAction::Chunk(chunk(0, b"da")));
    let ack = wire(&mut sessions, &first).await?;
    assert_eq!(wire(&mut sessions, &first).await?, ack);
    assert_eq!(
        server
            .monitor()
            .status()
            .transfers
            .get(&id)
            .ok_or("upload missing")?
            .confirmed_bytes,
        2
    );
    let changed = request(2, &id, WriteAction::Chunk(chunk(0, b"xx")));
    sessions
        .c
        .send(Channel::FileWrite, &changed.encode_validated()?)
        .await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), sessions.h.wait_stopped())
            .await??
            .reason,
        StopReason::ProtocolViolation
    );
    write_finished(&server.monitor()).await?;
    no_partial(&area)?;
    server.shutdown(StopReason::ExplicitExit).await?;
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn corrupt_chunk_offsets_and_chunks_beyond_manifest_are_rejected_before_writing() -> Result {
    for invalid in ["digest", "offset", "extent"] {
        let temporary = tempfile::tempdir()?;
        let area = temporary.path().join("received");
        let (root, roots, _keep) = writable(&area, 4, 4)?;
        let mut sessions =
            Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
        let mut server = FileWriteServer::start(&mut sessions.h, 9, roots)?;
        let id = random_id();
        wire(
            &mut sessions,
            &request(
                1,
                &id,
                WriteAction::Open(FileWriteOpen {
                    root_id: root,
                    path: "done".into(),
                    size: 4,
                    sha256: digest(b"data").to_vec(),
                }),
            ),
        )
        .await?;
        let mut bad = chunk(
            0,
            if invalid == "extent" {
                b"large"
            } else {
                b"data"
            },
        );
        if invalid == "digest" {
            bad.sha256 = vec![0; 32];
        }
        if invalid == "offset" {
            bad.offset = 1;
        }
        let bad = request(2, &id, WriteAction::Chunk(bad));
        if invalid == "digest" {
            let reply = wire(&mut sessions, &bad).await?;
            assert!(
                matches!(reply.action, Some(WriteAction::Failure(failure)) if failure.code == FileWriteErrorCode::FileWriteChecksumMismatch as i32)
            );
        } else {
            sessions
                .c
                .send(Channel::FileWrite, &bad.encode_validated()?)
                .await?;
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), sessions.h.wait_stopped())
                    .await??
                    .reason,
                StopReason::ProtocolViolation
            );
        }
        written(&server.monitor(), &id, |state| {
            state.file_closed && state.temporary_removed
        })
        .await?;
        assert!(!area.join("done").exists());
        no_partial(&area)?;
        server.shutdown(StopReason::ExplicitExit).await?;
        sessions.c.shutdown(StopReason::ExplicitExit).await?;
        sessions.h.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}

#[tokio::test]
async fn upload_activity_and_uuid_tombstones_remain_bounded() -> Result {
    let temporary = tempfile::tempdir()?;
    let area = temporary.path().join("received");
    let (root, roots, _keep) = writable(&area, 0, 0)?;
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
    let mut server = FileWriteServer::start(&mut sessions.h, 9, roots)?;
    let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
    let mut uploads = Vec::new();
    for _ in 0..FILE_WRITE_ACTIVE {
        uploads.push(
            client
                .open(&random_id(), &root, &random_id(), 0, digest(b""))
                .await?,
        );
    }
    assert_eq!(
        code(
            client
                .open(&random_id(), &root, "extra", 0, digest(b""))
                .await
                .err()
                .ok_or("active capacity was exceeded")?
        )?,
        FileWriteErrorCode::FileWriteCapacity
    );
    let closed_id = uploads[0].id().to_owned();
    for upload in &mut uploads {
        client.cancel(upload).await?;
    }
    assert!(
        client
            .open(&closed_id, &root, "again", 0, digest(b""))
            .await
            .is_err()
    );
    fs::write(area.join("existing"), b"")?;
    for _ in FILE_WRITE_ACTIVE..FILE_WRITE_TRANSFERS {
        assert_eq!(
            code(
                client
                    .open(&random_id(), &root, "existing", 0, digest(b""))
                    .await
                    .err()
                    .ok_or("an existing target was reopened")?
            )?,
            FileWriteErrorCode::FileWriteExists
        );
    }
    assert_eq!(
        server.monitor().status().transfers.len() as u64,
        FILE_WRITE_TRANSFERS
    );
    assert_eq!(
        code(
            client
                .open(&random_id(), &root, "over-limit", 0, digest(b""))
                .await
                .err()
                .ok_or("UUID tombstone capacity was exceeded")?
        )?,
        FileWriteErrorCode::FileWriteCapacity
    );
    assert!(!area.join("over-limit").exists());
    client.retire()?;
    no_partial(&area)?;
    server.shutdown(StopReason::ExplicitExit).await?;
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn abandoned_idle_destinations_expire_and_clean_even_when_viewing_continues() -> Result {
    let temporary = tempfile::tempdir()?;
    let area = temporary.path().join("received");
    let (root, roots, _keep) = writable(&area, 4, 4)?;
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
    let mut server =
        FileWriteServer::start_with_budget(&mut sessions.h, 9, roots, Duration::from_millis(500))?;
    let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
    let mut upload = client
        .open(&random_id(), &root, "done", 4, digest(b"data"))
        .await?;
    written(&server.monitor(), upload.id(), |state| {
        state.file_closed && state.temporary_removed
    })
    .await?;
    assert_eq!(
        code(
            client
                .write_chunk(&mut upload, chunk(0, b"data"))
                .await
                .err()
                .ok_or("idle destination resumed without approval")?
        )?,
        FileWriteErrorCode::FileWriteExpired
    );
    client.retire()?;
    sessions
        .c
        .send(Channel::Video, b"viewing after storage timeout")
        .await?;
    assert_eq!(
        sessions.h.receive().await?.payload,
        b"viewing after storage timeout"
    );
    assert!(!area.join("done").exists());
    no_partial(&area)?;
    server.shutdown(StopReason::ExplicitExit).await?;
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum BlockAt {
    Cleanup,
    AfterPublish,
    CapacityAndCleanup,
    CapacityAndPersistentCleanupFailure,
}
struct Gate {
    entered: AtomicBool,
    released: Mutex<bool>,
    wake: Condvar,
}
impl Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            wake: Condvar::new(),
        })
    }
    fn block(&self) {
        self.entered.store(true, Ordering::Release);
        let mut released = self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*released {
            released = self
                .wake
                .wait(released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
    fn release(&self) {
        *self
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.wake.notify_all();
    }
    async fn entered(&self) -> Result {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !self.entered.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await?;
        Ok(())
    }
}
struct Release(Arc<Gate>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}
struct BlockDevice {
    inner: WriteRoots,
    gate: Arc<Gate>,
    at: BlockAt,
}
struct BlockDestination {
    inner: Box<dyn FileWriteDestination>,
    gate: Arc<Gate>,
    at: BlockAt,
    cleanup_attempted: bool,
}
impl FileWriteDevice for BlockDevice {
    fn retire_revoked(&mut self) {
        self.inner.retire_revoked();
    }
    fn build(
        &mut self,
        open: &FileWriteOpen,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileWriteDestination>> {
        Ok(Box::new(BlockDestination {
            inner: self.inner.build(open, authorized)?,
            gate: self.gate.clone(),
            at: self.at,
            cleanup_attempted: false,
        }))
    }
}
impl FileWriteDestination for BlockDestination {
    fn consent(&self) -> Arc<dyn FileWriteConsent> {
        self.inner.consent()
    }
    fn status(&self) -> FileWriteState {
        self.inner.status()
    }
    fn prepare(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.inner.prepare(authorized)
    }
    fn write(
        &mut self,
        chunk: &FileWriteChunk,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        if matches!(
            self.at,
            BlockAt::CapacityAndCleanup | BlockAt::CapacityAndPersistentCleanupFailure
        ) {
            self.inner.write(
                &self::chunk(chunk.offset, &chunk.data[..chunk.data.len() / 2]),
                authorized,
            )?;
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "injected storage capacity fault",
            ));
        }
        self.inner.write(chunk, authorized)
    }
    fn finish(&mut self, authorized: &mut dyn FnMut() -> io::Result<()>) -> io::Result<()> {
        self.inner.finish(authorized)?;
        if self.at == BlockAt::AfterPublish {
            self.gate.block();
        }
        Ok(())
    }
    fn cleanup(&mut self) -> io::Result<()> {
        if self.at == BlockAt::CapacityAndPersistentCleanupFailure
            || self.at == BlockAt::CapacityAndCleanup && !self.cleanup_attempted
        {
            self.cleanup_attempted = true;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected cleanup fault",
            ));
        }
        if self.at == BlockAt::Cleanup {
            self.gate.block();
        }
        self.inner.cleanup()
    }
}

#[tokio::test]
async fn capacity_failure_preserves_real_partial_and_failed_cleanup_then_exact_cancel_retry_closes_it()
-> Result {
    let temporary = tempfile::tempdir()?;
    let area = temporary.path().join("received");
    let (root, roots, _keep) = writable(&area, 4, 4)?;
    let gate = Gate::new();
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
    let mut server = FileWriteServer::start(
        &mut sessions.h,
        9,
        BlockDevice {
            inner: roots,
            gate,
            at: BlockAt::CapacityAndCleanup,
        },
    )?;
    let monitor = server.monitor();
    let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
    let id = random_id();
    let mut upload = client.open(&id, &root, "done", 4, digest(b"data")).await?;
    assert_eq!(
        code(
            client
                .write_chunk(&mut upload, chunk(0, b"data"))
                .await
                .err()
                .ok_or("injected capacity failure was ignored")?
        )?,
        FileWriteErrorCode::FileWriteCapacity
    );
    assert_eq!(upload.offset(), 0);
    let state = upload
        .destination_state()
        .ok_or("actual dirty partial facts missing")?;
    assert_eq!(state.confirmed_bytes, 2);
    assert!(!state.file_closed && !state.temporary_removed && !state.published);
    assert!(!client.is_idle());
    assert_eq!(monitor.status().error, Some(io::ErrorKind::StorageFull));
    assert_eq!(
        monitor.status().cleanup_error,
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(fs::read_dir(&area)?.count(), 1);
    let cleaned = client.cancel(&mut upload).await?;
    assert!(cleaned.file_closed && cleaned.temporary_removed && !cleaned.published);
    assert!(client.is_idle());
    no_partial(&area)?;
    assert!(!area.join("done").exists());
    assert_eq!(
        monitor.status().cleanup_error,
        Some(io::ErrorKind::PermissionDenied)
    );
    client.retire()?;
    sessions
        .c
        .send(Channel::Video, b"viewing after actual cleanup retry")
        .await?;
    assert_eq!(
        sessions.h.receive().await?.payload,
        b"viewing after actual cleanup retry"
    );
    server.shutdown(StopReason::ExplicitExit).await?;
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
#[tokio::test]
async fn final_destination_drop_closes_real_handles_without_inventing_failed_temporary_removal()
-> Result {
    let temporary = tempfile::tempdir()?;
    let area = temporary.path().join("received");
    let (root, roots, _keep) = writable(&area, 4, 4)?;
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
    let mut server = FileWriteServer::start(
        &mut sessions.h,
        9,
        BlockDevice {
            inner: roots,
            gate: Gate::new(),
            at: BlockAt::CapacityAndPersistentCleanupFailure,
        },
    )?;
    let monitor = server.monitor();
    let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
    let id = random_id();
    let mut upload = client.open(&id, &root, "done", 4, digest(b"data")).await?;
    assert_eq!(
        code(
            client
                .write_chunk(&mut upload, chunk(0, b"data"))
                .await
                .err()
                .ok_or("persistent cleanup failure was ignored")?
        )?,
        FileWriteErrorCode::FileWriteCapacity
    );
    assert!(
        !upload
            .destination_state()
            .ok_or("partial facts missing")?
            .file_closed
    );
    assert_eq!(
        server.shutdown(StopReason::ExplicitExit).await?,
        FileShutdown::Finished
    );
    let state = monitor
        .status()
        .transfers
        .get(&id)
        .copied()
        .ok_or("final destination facts missing")?;
    assert!(state.file_closed && !state.temporary_removed && !state.published);
    assert_eq!(state.confirmed_bytes, 2);
    assert_eq!(
        monitor.status().cleanup_error,
        Some(io::ErrorKind::PermissionDenied)
    );
    let staged = fs::read_dir(&area)?
        .next()
        .ok_or("failed removal was incorrectly reported as successful")??
        .path();
    // In particular, the original Windows non-write-sharing handle is gone.
    let reopened = fs::OpenOptions::new().read(true).write(true).open(staged)?;
    assert_eq!(reopened.metadata()?.len(), 2);
    drop(reopened);
    drop(client);
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
#[tokio::test]
async fn blocked_cleanup_times_out_truthfully_then_closes_real_staging() -> Result {
    let temporary = tempfile::tempdir()?;
    let area = temporary.path().join("received");
    let (root, roots, _keep) = writable(&area, 4, 4)?;
    let gate = Gate::new();
    let _release = Release(gate.clone());
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
    let mut server = FileWriteServer::start(
        &mut sessions.h,
        9,
        BlockDevice {
            inner: roots,
            gate: gate.clone(),
            at: BlockAt::Cleanup,
        },
    )?;
    let monitor = server.monitor();
    let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
    let id = random_id();
    let mut upload = client.open(&id, &root, "done", 4, digest(b"data")).await?;
    client.write_chunk(&mut upload, chunk(0, b"da")).await?;
    sessions.stops[1].send_replace(Some(StopReason::Revoked));
    gate.entered().await?;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), sessions.h.wait_stopped())
            .await??
            .reason,
        StopReason::Revoked
    );
    assert_eq!(
        server.shutdown(StopReason::Revoked).await?,
        FileShutdown::TimedOut
    );
    assert!(!monitor.status().finished);
    assert!(monitor.status().cleanup_timed_out);
    assert!(
        !monitor
            .status()
            .transfers
            .get(&id)
            .ok_or("partial state missing")?
            .file_closed
    );
    assert!(fs::read_dir(&area)?.next().is_some());
    gate.release();
    write_finished(&monitor).await?;
    let actual = monitor
        .status()
        .transfers
        .get(&id)
        .cloned()
        .ok_or("cleanup state missing")?;
    assert!(actual.file_closed && actual.temporary_removed && !actual.published);
    assert!(monitor.status().cleanup_timed_out);
    no_partial(&area)?;
    server.shutdown(StopReason::Revoked).await?;
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
#[tokio::test]
async fn publication_returning_after_deadline_is_recorded_but_never_delivered_as_success() -> Result
{
    let temporary = tempfile::tempdir()?;
    let area = temporary.path().join("received");
    let (root, roots, _keep) = writable(&area, 4, 4)?;
    let gate = Gate::new();
    let _release = Release(gate.clone());
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
    let mut server = FileWriteServer::start_with_budget(
        &mut sessions.h,
        9,
        BlockDevice {
            inner: roots,
            gate: gate.clone(),
            at: BlockAt::AfterPublish,
        },
        Duration::from_millis(500),
    )?;
    let monitor = server.monitor();
    let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
    let id = random_id();
    let mut upload = client.open(&id, &root, "done", 4, digest(b"data")).await?;
    client.write_chunk(&mut upload, chunk(0, b"data")).await?;
    let waiting = client.commit(&mut upload);
    tokio::pin!(waiting);
    tokio::select! { result = &mut waiting => return Err(format!("blocked publication unexpectedly ended: {result:?}").into()), result = gate.entered() => result? }
    assert_eq!(fs::read(area.join("done"))?, b"data");
    assert!(
        tokio::time::timeout(Duration::from_secs(2), &mut waiting)
            .await?
            .is_err()
    );
    assert_eq!(
        server.shutdown(StopReason::ExplicitExit).await?,
        FileShutdown::TimedOut
    );
    assert!(!monitor.status().finished);
    gate.release();
    write_finished(&monitor).await?;
    let actual = monitor
        .status()
        .transfers
        .get(&id)
        .cloned()
        .ok_or("late publication lost actual facts")?;
    assert!(actual.published && actual.file_closed && actual.temporary_removed);
    assert_eq!(fs::read(area.join("done"))?, b"data");
    assert!(monitor.status().cleanup_timed_out);
    no_partial(&area)?;
    server.shutdown(StopReason::ExplicitExit).await?;
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn actual_staged_bytes_are_rehashed_and_windows_blocks_other_writers() -> Result {
    let temporary = tempfile::tempdir()?;
    let area = temporary.path().join("received");
    let (root, roots, _keep) = writable(&area, 4, 4)?;
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
    let mut server = FileWriteServer::start(&mut sessions.h, 9, roots)?;
    let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
    let mut upload = client
        .open(&random_id(), &root, "done", 4, digest(b"data"))
        .await?;
    client.write_chunk(&mut upload, chunk(0, b"data")).await?;
    let staged = fs::read_dir(&area)?
        .next()
        .ok_or("no actual staged file")??
        .path();
    #[cfg(unix)]
    {
        fs::write(&staged, b"evil")?;
        assert_eq!(
            code(
                client
                    .commit(&mut upload)
                    .await
                    .err()
                    .ok_or("actual corrupted disk bytes were published")?
            )?,
            FileWriteErrorCode::FileWriteChecksumMismatch
        );
        assert!(!area.join("done").exists());
    }
    #[cfg(windows)]
    {
        assert!(fs::OpenOptions::new().write(true).open(&staged).is_err());
        client.commit(&mut upload).await?;
        assert_eq!(fs::read(area.join("done"))?, b"data");
    }
    no_partial(&area)?;
    client.retire()?;
    server.shutdown(StopReason::ExplicitExit).await?;
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn no_follow_parent_lookup_rejects_symlinks_and_windows_junctions() -> Result {
    let temporary = tempfile::tempdir()?;
    let area = temporary.path().join("received");
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside)?;
    let (root, roots, _keep) = writable(&area, 4, 4)?;
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
    let mut server = FileWriteServer::start(&mut sessions.h, 9, roots)?;
    let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
    let mut first = client
        .open(&random_id(), &root, "initialization", 0, digest(b""))
        .await?;
    client.cancel(&mut first).await?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, area.join("link"))?;
    #[cfg(windows)]
    {
        let output = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(area.join("link"))
            .arg(&outside)
            .output()?;
        assert!(output.status.success(), "junction fixture creation failed");
    }
    assert!(
        client
            .open(&random_id(), &root, "link/escaped", 4, digest(b"data"))
            .await
            .is_err()
    );
    assert!(fs::read_dir(&outside)?.next().is_none());
    #[cfg(unix)]
    fs::remove_file(area.join("link"))?;
    #[cfg(windows)]
    fs::remove_dir(area.join("link"))?;
    no_partial(&area)?;
    client.retire()?;
    server.shutdown(StopReason::ExplicitExit).await?;
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

struct BlockingSourceFactory {
    inner: LocalUploadSelection,
    gate: Arc<Gate>,
}
struct BlockingSource {
    inner: Box<dyn FileReadSource>,
    gate: Arc<Gate>,
}
impl FileUploadSourceFactory for BlockingSourceFactory {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.inner.consent()
    }
    fn open(
        self: Box<Self>,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn FileReadSource>> {
        Ok(Box::new(BlockingSource {
            inner: Box::new(self.inner).open(authorized)?,
            gate: self.gate,
        }))
    }
}
impl FileReadSource for BlockingSource {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.inner.consent()
    }
    fn describe(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadManifest> {
        let manifest = self.inner.describe(authorized)?;
        self.gate.block();
        authorized()?;
        Ok(manifest)
    }
    fn read_chunk(
        &mut self,
        offset: u64,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        self.inner.read_chunk(offset, maximum, authorized)
    }
    fn verify(
        &mut self,
        manifest: &FileReadManifest,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.inner.verify(manifest, authorized)
    }
}
#[tokio::test]
async fn local_source_revocation_reports_promptly_without_claiming_blocked_handles_closed() -> Result
{
    let temporary = tempfile::tempdir()?;
    let area = temporary.path().join("received");
    let local = temporary.path().join("source");
    fs::write(&local, b"data")?;
    let (root, roots, _keep) = writable(&area, 4, 4)?;
    let (selected, consent) = LocalUploadSelection::new(&local, 4)?;
    let gate = Gate::new();
    let _release = Release(gate.clone());
    let mut sessions = Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
    let mut server = FileWriteServer::start(&mut sessions.h, 9, roots)?;
    let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
    let id = random_id();
    {
        let waiting = client.upload_source(
            &id,
            &root,
            "done",
            BlockingSourceFactory {
                inner: selected,
                gate: gate.clone(),
            },
        );
        tokio::pin!(waiting);
        tokio::select! { result = &mut waiting => return Err(format!("blocked source unexpectedly ended: {result:?}").into()), result = gate.entered() => result? }
        consent.revoke();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), &mut waiting)
                .await?
                .is_err()
        );
    }
    let monitor = client
        .source_monitor()
        .ok_or("source cleanup monitor missing")?;
    assert!(!monitor.status().finished && !monitor.status().source_closed);
    assert!(monitor.status().cleanup_timed_out);
    assert!(!area.exists());
    assert!(client.is_protocol_idle() && !client.is_idle());
    let (replacement, _keep_replacement) = LocalUploadSelection::new(&local, 4)?;
    assert!(matches!(
        client
            .upload_source(&random_id(), &root, "replacement", replacement)
            .await,
        Err(FileWriteError::Source(error)) if error.kind() == io::ErrorKind::WouldBlock
    ));
    assert!(!monitor.status().finished && !area.exists());
    gate.release();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !monitor.status().finished {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await?;
    assert!(monitor.status().source_closed && monitor.status().cleanup_timed_out);
    assert!(!monitor.status().source_verified);
    client.retire()?;
    sessions
        .c
        .send(Channel::Video, b"viewing after source revocation")
        .await?;
    assert_eq!(
        sessions.h.receive().await?.payload,
        b"viewing after source revocation"
    );
    server.shutdown(StopReason::ExplicitExit).await?;
    sessions.c.shutdown(StopReason::ExplicitExit).await?;
    sessions.h.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn a_proved_peer_cannot_substitute_ready_ack_identity_or_actions() -> Result {
    for tamper in [
        "transfer",
        "generation",
        "sequence",
        "action",
        "ready",
        "ack",
    ] {
        let mut sessions =
            Sessions::new(false, vec![Permission::View, Permission::FileWrite]).await?;
        let mut client = FileWriteClient::attach(&mut sessions.c, 9)?;
        let id = random_id();
        let root = random_id();
        let fake = async {
            let request = sessions.h.receive().await?;
            let mut reply = NativeFileWrite::decode_validated(&request.payload)?;
            let Some(WriteAction::Open(open)) = reply.action.take() else {
                return Err("fake peer expected Open".into());
            };
            reply.action = Some(WriteAction::Ready(nestlink_protocol::FileWriteReady {
                size: if tamper == "ready" {
                    open.size + 1
                } else {
                    open.size
                },
                sha256: open.sha256,
                offset: 0,
            }));
            if tamper == "transfer" {
                reply.transfer_id = random_id();
            }
            if tamper == "generation" {
                reply.connection_generation = 10;
            }
            if tamper == "sequence" {
                reply.sequence += 1;
            }
            if tamper == "action" {
                reply.action = Some(WriteAction::Ack(nestlink_protocol::FileWriteAck {
                    offset: 4,
                }));
            }
            sessions
                .h
                .send(Channel::FileWrite, &reply.encode_validated()?)
                .await?;
            if tamper == "ack" {
                let request = sessions.h.receive().await?;
                let mut reply = NativeFileWrite::decode_validated(&request.payload)?;
                reply.action = Some(WriteAction::Ack(nestlink_protocol::FileWriteAck {
                    offset: 3,
                }));
                sessions
                    .h
                    .send(Channel::FileWrite, &reply.encode_validated()?)
                    .await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let operation = async {
            match client.open(&id, &root, "done", 4, digest(b"data")).await {
                Ok(mut upload) if tamper == "ack" => client
                    .write_chunk(&mut upload, chunk(0, b"data"))
                    .await
                    .map(|_| ()),
                Ok(_) => panic!("substituted Ready was accepted"),
                Err(error) => Err(error),
            }
        };
        let (result, fake) = tokio::join!(operation, fake);
        fake?;
        assert!(result.is_err());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), sessions.c.wait_stopped())
                .await??
                .reason,
            StopReason::ProtocolViolation
        );
        sessions.c.shutdown(StopReason::ExplicitExit).await?;
        sessions.h.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}
