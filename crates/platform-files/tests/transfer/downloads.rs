use super::*;
use nestlink_platform_files::download::LocalDownload;

#[tokio::test]
async fn authorization_failure_at_each_write_boundary_preserves_actual_prefix_and_verifier()
-> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    let bytes = b"exact callback boundary object";
    fs::write(source.path().join("source"), bytes)?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
    let baseline_area = output.path().join("baseline");
    let (mut baseline, consent) =
        LocalDownload::create(&baseline_area, "done", FILE_SIZE_BYTES, &download)?;
    let chunk = client.next(&mut download).await?.ok_or("missing chunk")?;
    let mut boundary_count = 0;
    baseline.write_chunk(&download, &chunk, &mut || {
        boundary_count += 1;
        Ok(())
    })?;
    assert!(boundary_count > 1);
    let mut copies = vec![(baseline, consent, baseline_area)];
    // Exercise the real file operations on each side of every actual callback,
    // including the final check after bytes were committed. No fixed callback
    // count is assumed and no synthetic FileDownload identity is created.
    for cutoff in 1..=boundary_count {
        let area = output.path().join(format!("boundary-{cutoff}"));
        // Obtain another exact source for each independent destination.
        let mut candidate = client.open(&random_id(), &id, "source", 0, None).await?;
        let (mut disk, consent) =
            LocalDownload::create(&area, "done", FILE_SIZE_BYTES, &candidate)?;
        let exact = client
            .next(&mut candidate)
            .await?
            .ok_or("missing candidate chunk")?;
        let mut calls = 0;
        assert_eq!(
            disk.write_chunk(&candidate, &exact, &mut || {
                calls += 1;
                if calls == cutoff {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "boundary denied",
                    ))
                } else {
                    Ok(())
                }
            })
            .err()
            .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied),
            "cutoff={cutoff}"
        );
        assert!(!disk.status().poisoned, "cutoff={cutoff}");
        let staged = fs::read_dir(&area)?
            .next()
            .ok_or("missing staged file")??
            .path();
        let actual = fs::read(&staged)?;
        assert_eq!(actual.len() as u64, disk.status().confirmed_bytes);
        if actual.is_empty() {
            // Retry is meaningful: a prematurely advanced verifier would reject
            // this original exact block even though disk bytes never changed.
            disk.write_chunk(&candidate, &exact, &mut || Ok(()))?;
        } else {
            assert_eq!(actual, bytes);
            assert!(
                disk.write_chunk(&candidate, &exact, &mut || Ok(()))
                    .is_err()
            );
        }
        assert!(client.next(&mut candidate).await?.is_none());
        disk.finish(&candidate, &mut || Ok(()))?;
        assert_eq!(fs::read(area.join("done"))?, bytes);
        copies.push((disk, consent, area));
    }
    assert!(client.next(&mut download).await?.is_none());
    copies[0].0.finish(&download, &mut || Ok(()))?;
    client.retire()?;
    s.c.lease_control().check_media_binding(Channel::Video, 9)?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn verified_private_downloads_publish_atomically_over_real_tls_and_quic() -> Result {
    for quic in [false, true] {
        let source = tempfile::tempdir()?;
        let output = tempfile::tempdir()?;
        let bytes: Vec<_> = (0..256 * 1024 + 91).map(|i| (i % 251) as u8).collect();
        fs::write(source.path().join("source"), &bytes)?;
        fs::write(source.path().join("empty"), b"")?;
        let (id, provider, _keep) = roots(source.path())?;
        let mut s = Sessions::new(quic, vec![Permission::View, Permission::FileRead]).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
        let mut client = FileReadClient::attach(&mut s.c, 9)?;
        for (source_name, final_name, expected) in [
            ("source", "文件.txt", bytes.as_slice()),
            ("empty", "empty", b"".as_slice()),
        ] {
            let area = output.path().join(random_id());
            let target = area.join(final_name);
            let mut download = client.open(&random_id(), &id, source_name, 0, None).await?;
            let (mut disk, _consent) =
                LocalDownload::create(&area, final_name, FILE_SIZE_BYTES, &download)?;
            assert!(!target.exists());
            assert!(disk.finish(&download, &mut || Ok(())).is_err());
            while let Some(chunk) = client.next(&mut download).await? {
                disk.write_chunk(&download, &chunk, &mut || Ok(()))?;
                assert!(!target.exists(), "partial output must not be published");
            }
            assert!(download.source_verified());
            let finished = disk.finish(&download, &mut || Ok(()))?;
            assert!(finished.published && finished.file_closed && finished.temporary_removed);
            assert!(!finished.poisoned);
            #[cfg(unix)]
            assert!(finished.directory_synced);
            #[cfg(windows)]
            assert!(!finished.directory_synced);
            assert_eq!(fs::read(&target)?, expected);
            assert_eq!(fs::read_dir(&area)?.count(), 1);
            // Cleanup is idempotent and never deletes a published object.
            assert!(disk.cancel()?.published);
            assert_eq!(fs::read(&target)?, expected);
        }
        server.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}

#[tokio::test]
async fn actual_disk_prefix_is_rebound_and_verified_before_resuming_a_new_transfer() -> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    let bytes: Vec<_> = (0..200 * 1024 + 13).map(|i| (i % 239) as u8).collect();
    fs::write(source.path().join("source"), &bytes)?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut first = client.open(&random_id(), &id, "source", 0, None).await?;
    let hash: [u8; 32] = first.manifest().sha256.as_slice().try_into()?;
    let area = output.path().join("resumed");
    let (mut disk, _consent) = LocalDownload::create(&area, "done", FILE_SIZE_BYTES, &first)?;
    let chunk = client
        .next(&mut first)
        .await?
        .ok_or("missing initial chunk")?;
    disk.write_chunk(&first, &chunk, &mut || Ok(()))?;
    client.cancel(&mut first).await?;
    assert!(first.finished() && !first.source_verified());
    assert!(disk.finish(&first, &mut || Ok(())).is_err());
    let offset = disk.status().confirmed_bytes;
    let mut resumed = client
        .open(&random_id(), &id, "source", offset, Some(hash))
        .await?;
    let next = client
        .next(&mut resumed)
        .await?
        .ok_or("missing resumed chunk")?;
    assert!(
        disk.write_chunk(&resumed, &next, &mut || Ok(())).is_err(),
        "different transfer must not silently replace the original binding"
    );
    // That response advanced the client. Reopen exactly at the local disk prefix.
    client.cancel(&mut resumed).await?;
    let mut resumed = client
        .open(&random_id(), &id, "source", offset, Some(hash))
        .await?;
    disk.resume(&resumed, &mut || Ok(()))?;
    while let Some(chunk) = client.next(&mut resumed).await? {
        disk.write_chunk(&resumed, &chunk, &mut || Ok(()))?;
    }
    disk.finish(&resumed, &mut || Ok(()))?;
    assert_eq!(fs::read(area.join("done"))?, bytes);
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn cancelled_source_local_revoke_and_conflicting_target_never_report_saved_success() -> Result
{
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("source"), b"authorized exact object")?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    for mode in [
        "cancel",
        "local-revoke",
        "existing-file",
        "existing-link",
        "existing-directory",
    ] {
        let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
        let area = output.path().join(mode);
        let target = area.join("done");
        let (mut disk, consent) = LocalDownload::create(&area, "done", 30, &download)?;
        let chunk = client.next(&mut download).await?.ok_or("missing chunk")?;
        disk.write_chunk(&download, &chunk, &mut || Ok(()))?;
        if mode == "cancel" {
            client.cancel(&mut download).await?;
            assert!(!download.source_verified());
            assert!(disk.write_chunk(&download, &chunk, &mut || Ok(())).is_err());
        } else {
            assert!(client.next(&mut download).await?.is_none());
        }
        match mode {
            "local-revoke" => consent.revoke(),
            "existing-file" => fs::write(&target, b"must remain")?,
            "existing-link" => {
                let victim = area.join("victim");
                fs::write(&victim, b"must remain")?;
                fs::hard_link(&victim, &target)?;
            }
            "existing-directory" => fs::create_dir(&target)?,
            _ => {}
        }
        assert!(disk.finish(&download, &mut || Ok(())).is_err(), "{mode}");
        assert!(!disk.status().published, "{mode}");
        let cancelled = disk.cancel()?;
        assert!(cancelled.file_closed && cancelled.temporary_removed && cancelled.poisoned);
        match mode {
            "existing-file" | "existing-link" => assert_eq!(fs::read(&target)?, b"must remain"),
            "existing-directory" => assert!(target.is_dir()),
            _ => assert!(!target.exists()),
        }
    }
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn locally_chosen_fresh_area_name_and_size_are_required_before_creating_output() -> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("source"), b"content")?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
    for name in [
        "../escape",
        "nested/file",
        "NUL",
        "file:stream",
        "C:/escape",
        "file.",
    ] {
        let area = output.path().join(random_id());
        assert!(LocalDownload::create(&area, name, 50, &download).is_err());
        assert!(!area.exists());
    }
    let too_small = output.path().join("small");
    assert!(LocalDownload::create(&too_small, "done", 2, &download).is_err());
    assert!(!too_small.exists());
    assert!(LocalDownload::create(output.path(), "done", 50, &download).is_err());
    client.cancel(&mut download).await?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn cached_chunk_after_cancel_and_verified_end_after_session_revoke_do_not_authorize_disk_output()
-> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("source"), b"source bytes")?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut cancelled = client.open(&random_id(), &id, "source", 0, None).await?;
    let first_area = output.path().join("cancelled");
    let (mut disk, _consent) = LocalDownload::create(&first_area, "done", 20, &cancelled)?;
    let chunk = client.next(&mut cancelled).await?.ok_or("missing chunk")?;
    client.cancel(&mut cancelled).await?;
    assert!(
        disk.write_chunk(&cancelled, &chunk, &mut || Ok(()))
            .is_err()
    );
    assert_eq!(disk.status().confirmed_bytes, 0);
    disk.cancel()?;
    assert!(!first_area.join("done").exists());
    let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
    let final_area = output.path().join("revoked");
    let (mut disk, _consent) = LocalDownload::create(&final_area, "done", 20, &download)?;
    let lease = s.c.lease_control();
    let mut authorized = || {
        lease
            .check_channel_binding(Channel::FileRead, 9)
            .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "session stopped"))
    };
    while let Some(chunk) = client.next(&mut download).await? {
        disk.write_chunk(&download, &chunk, &mut authorized)?;
    }
    assert!(download.source_verified());
    lease.stop(StopReason::Revoked)?;
    assert!(disk.finish(&download, &mut authorized).is_err());
    assert!(!disk.status().published);
    disk.cancel()?;
    assert!(!final_area.join("done").exists());
    server.shutdown(StopReason::Revoked).await?;
    Ok(())
}

#[tokio::test]
async fn valid_per_chunk_hashes_cannot_substitute_a_different_complete_local_object() -> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("source"), b"original source")?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
    let area = output.path().join("different-content");
    let (mut disk, _consent) = LocalDownload::create(&area, "done", 30, &download)?;
    let mut chunk = client.next(&mut download).await?.ok_or("missing chunk")?;
    chunk.data[0] ^= 1;
    chunk.sha256 = digest(&chunk.data).to_vec();
    disk.write_chunk(&download, &chunk, &mut || Ok(()))?;
    assert!(client.next(&mut download).await?.is_none());
    assert!(download.source_verified());
    assert!(disk.finish(&download, &mut || Ok(())).is_err());
    assert!(disk.status().poisoned && !disk.status().published);
    assert!(!area.join("done").exists());
    disk.cancel()?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn local_directory_handle_pins_atomic_output_and_no_clobber_failure_keeps_the_verified_stage()
-> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("source"), b"approved staged output")?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
    let area = output.path().join("selected-area");
    let renamed = output.path().join("original-object");
    let (mut disk, _consent) = LocalDownload::create(&area, "done", 30, &download)?;
    #[cfg(unix)]
    {
        fs::rename(&area, &renamed)?;
        fs::create_dir(&area)?;
    }
    #[cfg(windows)]
    assert_eq!(
        fs::rename(&area, &renamed)
            .err()
            .and_then(|e| e.raw_os_error()),
        Some(32)
    );
    #[cfg(unix)]
    let actual = &renamed;
    #[cfg(windows)]
    let actual = &area;
    while let Some(chunk) = client.next(&mut download).await? {
        disk.write_chunk(&download, &chunk, &mut || Ok(()))?;
    }
    let target = actual.join("done");
    fs::write(&target, b"local existing object")?;
    assert!(disk.finish(&download, &mut || Ok(())).is_err());
    assert!(!disk.status().published && !disk.status().poisoned);
    assert_eq!(fs::read(&target)?, b"local existing object");
    // An explicit local action removes the test-owned conflict; the complete
    // verified original stage remains available for a no-clobber retry.
    fs::remove_file(&target)?;
    let saved = disk.finish(&download, &mut || Ok(()))?;
    assert!(saved.published && saved.temporary_removed);
    assert_eq!(fs::read(&target)?, b"approved staged output");
    #[cfg(unix)]
    assert!(
        !area.join("done").exists(),
        "ambient path replacement must not redirect publication"
    );
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn existing_target_symlink_is_not_followed_or_replaced() -> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("source"), b"verified incoming")?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
    let area = output.path().join("selected");
    let (mut disk, _consent) = LocalDownload::create(&area, "done", 30, &download)?;
    let victim = output.path().join("other-local-object");
    fs::write(&victim, b"must remain")?;
    std::os::unix::fs::symlink(&victim, area.join("done"))?;
    while let Some(chunk) = client.next(&mut download).await? {
        disk.write_chunk(&download, &chunk, &mut || Ok(()))?;
    }
    assert!(disk.finish(&download, &mut || Ok(())).is_err());
    assert!(!disk.status().published);
    assert!(fs::symlink_metadata(area.join("done"))?.is_symlink());
    assert_eq!(fs::read(&victim)?, b"must remain");
    disk.cancel()?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn identical_uuid_and_manifest_from_another_proven_client_do_not_match_the_local_binding()
-> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("source"), b"same source identity")?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let uuid = random_id();
    let mut first = client.open(&uuid, &id, "source", 0, None).await?;
    let binding = first.binding();
    let area = output.path().join("bound");
    let (mut disk, _consent) = LocalDownload::create(&area, "done", 30, &first)?;
    let (other_id, other_provider, _other_keep) = roots(source.path())?;
    let mut other = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut other_server = FileReadServer::start(&mut other.h, 9, other_provider)?;
    let mut other_client = FileReadClient::attach(&mut other.c, 9)?;
    let mut second = other_client
        .open(&uuid, &other_id, "source", 0, None)
        .await?;
    assert_eq!(first.manifest(), second.manifest());
    assert!(!binding.matches(&second));
    let chunk = other_client
        .next(&mut second)
        .await?
        .ok_or("missing chunk")?;
    assert!(disk.write_chunk(&second, &chunk, &mut || Ok(())).is_err());
    assert_eq!(disk.status().confirmed_bytes, 0);
    assert!(!disk.status().published);
    disk.cancel()?;
    client.cancel(&mut first).await?;
    other_client.cancel(&mut second).await?;
    server.shutdown(StopReason::ExplicitExit).await?;
    other_server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn changed_actual_disk_prefix_and_complete_bytes_are_rejected_before_publication() -> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("source"), vec![19; 80 * 1024])?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    for stage in ["prefix", "complete"] {
        let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
        let hash: [u8; 32] = download.manifest().sha256.as_slice().try_into()?;
        let area = output.path().join(stage);
        let (mut disk, _consent) =
            LocalDownload::create(&area, "done", FILE_SIZE_BYTES, &download)?;
        let chunk = client.next(&mut download).await?.ok_or("missing chunk")?;
        disk.write_chunk(&download, &chunk, &mut || Ok(()))?;
        if stage == "complete" {
            while let Some(chunk) = client.next(&mut download).await? {
                disk.write_chunk(&download, &chunk, &mut || Ok(()))?;
            }
        } else {
            client.cancel(&mut download).await?;
        }
        let part = fs::read_dir(&area)?
            .next()
            .ok_or("missing temporary entry")??
            .path();
        let original_size = fs::metadata(&part)?.len();
        fs::write(&part, vec![20; original_size as usize])?;
        if stage == "prefix" {
            let mut resumed = client
                .open(
                    &random_id(),
                    &id,
                    "source",
                    disk.status().confirmed_bytes,
                    Some(hash),
                )
                .await?;
            assert!(disk.resume(&resumed, &mut || Ok(())).is_err());
            client.cancel(&mut resumed).await?;
        } else {
            assert!(disk.finish(&download, &mut || Ok(())).is_err());
        }
        assert!(disk.status().poisoned && !disk.status().published);
        assert!(!area.join("done").exists());
        disk.cancel()?;
    }
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
async fn private_staged_windows_handle_prevents_concurrent_write_or_replacement() -> Result {
    let source = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(source.path().join("source"), b"pinned stage")?;
    let (id, provider, _keep) = roots(source.path())?;
    let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut download = client.open(&random_id(), &id, "source", 0, None).await?;
    let area = output.path().join("pinned");
    let (mut disk, _consent) = LocalDownload::create(&area, "done", 30, &download)?;
    let part = fs::read_dir(&area)?.next().ok_or("missing stage")??.path();
    assert_eq!(
        fs::write(&part, b"malicious edit")
            .err()
            .and_then(|e| e.raw_os_error()),
        Some(32)
    );
    assert_eq!(
        fs::rename(&part, area.join("replaced"))
            .err()
            .and_then(|e| e.raw_os_error()),
        Some(32)
    );
    assert_eq!(
        fs::remove_file(&part).err().and_then(|e| e.raw_os_error()),
        Some(32)
    );
    while let Some(chunk) = client.next(&mut download).await? {
        disk.write_chunk(&download, &chunk, &mut || Ok(()))?;
    }
    disk.finish(&download, &mut || Ok(()))?;
    assert_eq!(fs::read(area.join("done"))?, b"pinned stage");
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
