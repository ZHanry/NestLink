use super::*;
use nestlink_platform_files::browse::{
    BrowseConsent, BrowseLimits, BrowseSelection, network::BrowseRoots,
};
use nestlink_protocol::{
    DirectoryBrowseBegin, DirectoryBrowseNext, DirectoryBrowsePage, DirectoryEntryKind,
};

fn provider(
    path: &FsPath,
    limits: BrowseLimits,
) -> Result<(
    String,
    BrowseRoots<FileRoots>,
    BrowseConsent,
    ReadRootConsent,
)> {
    let (id, files, read_consent) = roots(path)?;
    let (selection, browse_consent) = BrowseSelection::new(&id, path, limits)?;
    Ok((
        id,
        BrowseRoots::new(files, vec![selection])?,
        browse_consent,
        read_consent,
    ))
}
async fn request(
    s: &mut Sessions,
    transfer: &str,
    sequence: u64,
    action: Action,
) -> Result<NativeFileRead> {
    let request = NativeFileRead {
        schema_version: SCHEMA_VERSION,
        connection_generation: 9,
        sequence,
        transfer_id: transfer.into(),
        action: Some(action),
    };
    s.c.send(Channel::FileRead, &request.encode_validated()?)
        .await?;
    let frame = tokio::time::timeout(Duration::from_secs(2), s.c.receive()).await??;
    assert_eq!(frame.channel, Channel::FileRead);
    let reply = NativeFileRead::decode_validated(&frame.payload)?;
    assert_eq!(
        (reply.sequence, reply.transfer_id.as_str()),
        (sequence, transfer)
    );
    Ok(reply)
}
fn begin(root: &str, directory: &str, maximum: u32) -> Action {
    Action::BrowseBegin(DirectoryBrowseBegin {
        root_id: root.into(),
        directory: directory.into(),
        maximum,
    })
}
fn page(reply: NativeFileRead) -> Result<DirectoryBrowsePage> {
    if let Some(Action::BrowsePage(page)) = reply.action {
        Ok(page)
    } else {
        Err("missing directory metadata page".into())
    }
}
fn is_failure(reply: &NativeFileRead, code: FileReadErrorCode) -> bool {
    matches!(&reply.action, Some(Action::Failure(failure)) if failure.code == code as i32)
}
async fn viewing(s: &mut Sessions) -> Result {
    s.h.send(Channel::Video, b"view remains approved").await?;
    let frame = tokio::time::timeout(Duration::from_secs(1), s.c.receive()).await??;
    assert_eq!(
        (frame.channel, frame.payload.as_slice()),
        (Channel::Video, &b"view remains approved"[..])
    );
    Ok(())
}

#[tokio::test]
async fn directory_tls_and_quic_pages_sort_metadata_and_share_one_client_with_downloads() -> Result
{
    for quic in [false, true] {
        let directory = tempfile::tempdir()?;
        fs::create_dir(directory.path().join("nested"))?;
        fs::write(directory.path().join("nested").join("中文.txt"), b"child")?;
        for index in (0..139).rev() {
            fs::write(directory.path().join(format!("item-{index:03}")), b"x")?;
        }
        let (id, provider, _browse_keep, _read_keep) =
            provider(directory.path(), BrowseLimits::default())?;
        let mut s = Sessions::new(quic, vec![Permission::View, Permission::FileRead]).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
        let mut client = FileReadClient::attach(&mut s.c, 9)?;
        let mut browse = client.begin_browse(&random_id(), &id, None, 128).await?;
        assert_eq!(
            (
                browse.page().offset,
                browse.page().total_entries,
                browse.page().entries.len()
            ),
            (0, 140, 128)
        );
        let original = browse.page().snapshot_id.clone();
        let mut names: Vec<_> = browse
            .page()
            .entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        let rest = client
            .next_browse(&mut browse, 128)
            .await?
            .ok_or("missing next page")?;
        assert_eq!((rest.offset, rest.entries.len()), (128, 12));
        assert_eq!(rest.snapshot_id, original);
        let nested = rest.entries.last().ok_or("missing nested directory")?;
        assert_eq!(
            (nested.name.as_str(), nested.kind, nested.size),
            (
                "nested",
                DirectoryEntryKind::DirectoryEntryDirectory as i32,
                None
            )
        );
        names.extend(rest.entries.iter().map(|entry| entry.name.clone()));
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(browse.finished());
        assert!(client.next_browse(&mut browse, 1).await?.is_none());
        let child = client
            .begin_browse(&random_id(), &id, Some("nested"), 10)
            .await?;
        assert_eq!(
            (
                child.page().entries[0].name.as_str(),
                child.page().entries[0].size
            ),
            ("中文.txt", Some(5))
        );
        let mut download = client
            .open(&random_id(), &id, "nested/中文.txt", 0, None)
            .await?;
        assert_eq!(
            client
                .next(&mut download)
                .await?
                .ok_or("missing file content")?
                .data,
            b"child"
        );
        assert!(client.next(&mut download).await?.is_none());
        client.retire()?;
        viewing(&mut s).await?;
        assert_eq!(
            server.shutdown(StopReason::ExplicitExit).await?,
            FileShutdown::Finished
        );
    }
    Ok(())
}

#[tokio::test]
async fn directory_local_consent_and_mutation_failures_preserve_file_read_and_view() -> Result {
    for quic in [false, true] {
        let directory = tempfile::tempdir()?;
        fs::write(directory.path().join("a"), b"a")?;
        fs::write(directory.path().join("b"), b"b")?;
        let (id, provider, browse_keep, _read_keep) =
            provider(directory.path(), BrowseLimits::default())?;
        let mut s = Sessions::new(quic, vec![Permission::View, Permission::FileRead]).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
        let mut client = FileReadClient::attach(&mut s.c, 9)?;
        let mut browse = client.begin_browse(&random_id(), &id, None, 1).await?;
        fs::write(directory.path().join("c"), b"c")?;
        assert!(matches!(
            client.next_browse(&mut browse, 1).await,
            Err(FileReadError::Source(FileReadErrorCode::FileReadChanged))
        ));
        viewing(&mut s).await?;
        let mut fresh = client.begin_browse(&random_id(), &id, None, 1).await?;
        assert_eq!(fresh.page().total_entries, 3);
        browse_keep.revoke();
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert!(matches!(
            client.next_browse(&mut fresh, 1).await,
            Err(FileReadError::Source(FileReadErrorCode::FileReadDenied))
        ));
        assert!(matches!(
            client.begin_browse(&random_id(), &id, None, 1).await,
            Err(FileReadError::Source(FileReadErrorCode::FileReadDenied))
        ));
        let mut file = client.open(&random_id(), &id, "a", 0, None).await?;
        assert_eq!(
            client
                .next(&mut file)
                .await?
                .ok_or("missing retained file")?
                .data,
            b"a"
        );
        client.cancel(&mut file).await?;
        viewing(&mut s).await?;
        assert_eq!(
            server.shutdown(StopReason::ExplicitExit).await?,
            FileShutdown::Finished
        );
    }
    Ok(())
}

#[tokio::test]
async fn directory_exact_retry_and_serialized_cursor_replay_do_not_refresh_snapshot() -> Result {
    for quic in [false, true] {
        let directory = tempfile::tempdir()?;
        for name in ["a", "b", "c"] {
            fs::write(directory.path().join(name), b"x")?;
        }
        let (id, provider, _keep, _read) = provider(directory.path(), BrowseLimits::default())?;
        let mut s = Sessions::new(quic, vec![Permission::View, Permission::FileRead]).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
        let transfer = random_id();
        let first = page(request(&mut s, &transfer, 1, begin(&id, "", 1)).await?)?;
        let retry = page(request(&mut s, &transfer, 1, begin(&id, "", 1)).await?)?;
        assert_eq!(first, retry);
        let next = Action::BrowseNext(DirectoryBrowseNext {
            cursor: first.next_cursor.clone(),
            maximum: 1,
        });
        let second = page(request(&mut s, &transfer, 2, next.clone()).await?)?;
        assert_eq!((second.offset, second.entries[0].name.as_str()), (1, "b"));
        assert_eq!(
            second,
            page(request(&mut s, &transfer, 2, next.clone()).await?)?
        );
        assert!(is_failure(
            &request(&mut s, &transfer, 3, next).await?,
            FileReadErrorCode::FileReadChanged
        ));
        viewing(&mut s).await?;
        assert_eq!(
            server.shutdown(StopReason::ExplicitExit).await?,
            FileShutdown::Finished
        );
    }
    Ok(())
}

#[tokio::test]
async fn directory_cached_pages_and_idle_cursors_expire_from_the_original_local_deadline() -> Result
{
    for quic in [false, true] {
        let directory = tempfile::tempdir()?;
        fs::write(directory.path().join("a"), b"a")?;
        fs::write(directory.path().join("b"), b"b")?;
        let limits = BrowseLimits::new(
            100,
            1000,
            Duration::from_secs(1),
            Duration::from_millis(150),
        )?;
        let (id, provider, _keep, _read) = provider(directory.path(), limits)?;
        let mut s = Sessions::new(quic, vec![Permission::View, Permission::FileRead]).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
        let transfer = random_id();
        let first = page(request(&mut s, &transfer, 1, begin(&id, "", 1)).await?)?;
        tokio::time::sleep(Duration::from_millis(170)).await;
        assert!(is_failure(
            &request(&mut s, &transfer, 1, begin(&id, "", 1)).await?,
            FileReadErrorCode::FileReadChanged
        ));
        assert!(is_failure(
            &request(
                &mut s,
                &transfer,
                2,
                Action::BrowseNext(DirectoryBrowseNext {
                    cursor: first.next_cursor,
                    maximum: 1
                })
            )
            .await?,
            FileReadErrorCode::FileReadChanged
        ));
        viewing(&mut s).await?;
        assert_eq!(
            server.shutdown(StopReason::ExplicitExit).await?,
            FileShutdown::Finished
        );
    }
    Ok(())
}

#[tokio::test]
async fn directory_and_downloads_share_the_four_active_limit_and_retire_rejected_ids() -> Result {
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join("a"), b"a")?;
    fs::write(directory.path().join("b"), b"b")?;
    let (id, provider, _keep, _read) = provider(directory.path(), BrowseLimits::default())?;
    let mut s = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let mut browse = client.begin_browse(&random_id(), &id, None, 1).await?;
    let mut reads = Vec::new();
    for _ in 0..3 {
        reads.push(client.open(&random_id(), &id, "a", 0, None).await?);
    }
    let candidate = random_id();
    assert!(matches!(
        client.begin_browse(&candidate, &id, None, 1).await,
        Err(FileReadError::Source(FileReadErrorCode::FileReadCapacity))
    ));
    client.cancel_browse(&mut browse).await?;
    let mut replacement = client.begin_browse(&candidate, &id, None, 1).await?;
    client.cancel_browse(&mut replacement).await?;
    assert!(client.begin_browse(&candidate, &id, None, 1).await.is_err());
    for download in &mut reads {
        client.cancel(download).await?;
    }
    viewing(&mut s).await?;
    assert_eq!(
        server.shutdown(StopReason::ExplicitExit).await?,
        FileShutdown::Finished
    );
    Ok(())
}

#[tokio::test]
async fn directory_cursor_cannot_move_between_root_transfers_or_client_instances() -> Result {
    let directory = tempfile::tempdir()?;
    for name in ["a", "b", "c"] {
        fs::write(directory.path().join(name), b"x")?;
    }
    let (id, provider, _keep, _read) = provider(directory.path(), BrowseLimits::default())?;
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, provider)?;
    let a = random_id();
    let b = random_id();
    let first = page(request(&mut s, &a, 1, begin(&id, "", 1)).await?)?;
    let second = page(request(&mut s, &b, 2, begin(&id, "", 1)).await?)?;
    assert_ne!(first.snapshot_id, second.snapshot_id);
    assert!(is_failure(
        &request(
            &mut s,
            &b,
            3,
            Action::BrowseNext(DirectoryBrowseNext {
                cursor: first.next_cursor.clone(),
                maximum: 1
            })
        )
        .await?,
        FileReadErrorCode::FileReadChanged
    ));
    assert_eq!(
        page(
            request(
                &mut s,
                &a,
                4,
                Action::BrowseNext(DirectoryBrowseNext {
                    cursor: first.next_cursor,
                    maximum: 1
                })
            )
            .await?
        )?
        .entries[0]
            .name,
        "b"
    );
    assert_eq!(
        server.shutdown(StopReason::ExplicitExit).await?,
        FileShutdown::Finished
    );

    let (id, provider, _keep, _read) = self::provider(directory.path(), BrowseLimits::default())?;
    let mut original = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut original.h, 9, provider)?;
    let mut client = FileReadClient::attach(&mut original.c, 9)?;
    let mut browse = client.begin_browse(&random_id(), &id, None, 1).await?;
    let mut foreign = Sessions::new(false, vec![Permission::View, Permission::FileRead]).await?;
    let mut other = FileReadClient::attach(&mut foreign.c, 9)?;
    assert!(other.next_browse(&mut browse, 1).await.is_err());
    assert_eq!(
        client
            .next_browse(&mut browse, 1)
            .await?
            .ok_or("original cursor lost")?
            .entries[0]
            .name,
        "b"
    );
    client.cancel_browse(&mut browse).await?;
    assert_eq!(
        server.shutdown(StopReason::ExplicitExit).await?,
        FileShutdown::Finished
    );
    Ok(())
}

#[tokio::test]
async fn directory_requires_file_read_and_its_local_root_never_grants_file_contents() -> Result {
    let directory = tempfile::tempdir()?;
    fs::write(directory.path().join("file"), b"secret")?;
    let id = random_id();
    let (selection, _keep) = BrowseSelection::new(&id, directory.path(), BrowseLimits::default())?;
    let browse_only = BrowseRoots::new(FileRoots::new(Vec::new())?, vec![selection])?;
    let mut forbidden = Sessions::new(false, vec![Permission::View]).await?;
    assert!(FileReadServer::start(&mut forbidden.h, 9, browse_only).is_err());
    assert!(FileReadClient::attach(&mut forbidden.c, 9).is_err());
    let (selection, _keep) = BrowseSelection::new(&id, directory.path(), BrowseLimits::default())?;
    let browse_only = BrowseRoots::new(FileRoots::new(Vec::new())?, vec![selection])?;
    let mut s = Sessions::new(true, vec![Permission::View, Permission::FileRead]).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, browse_only)?;
    assert!(FileReadClient::attach(&mut s.c, 8).is_err());
    let mut client = FileReadClient::attach(&mut s.c, 9)?;
    let metadata = client.begin_browse(&random_id(), &id, None, 1).await?;
    assert_eq!(metadata.page().entries[0].size, Some(6));
    assert!(matches!(
        client.open(&random_id(), &id, "file", 0, None).await,
        Err(FileReadError::Source(FileReadErrorCode::FileReadDenied))
    ));
    viewing(&mut s).await?;
    assert_eq!(
        server.shutdown(StopReason::ExplicitExit).await?,
        FileShutdown::Finished
    );
    Ok(())
}
