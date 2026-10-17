#![cfg(not(target_arch = "wasm32"))]
#[path = "files/support.rs"]
mod support;
use nestlink_auth::random_id;
use nestlink_platform_files::{
    ApprovedReadRoot, FileRoots, ReadRootConsent,
    browse::{BrowseConsent, BrowseLimits, BrowseSelection, network::BrowseRoots},
    download::LocalDownloadSelection,
};
use nestlink_protocol::{
    DIRECTORY_SNAPSHOT_MS, DirectoryBrowsePage, DirectoryEntry, DirectoryEntryKind,
    FILE_OPERATION_MS, FILE_SIZE_BYTES, FileReadErrorCode, NativeFileRead,
    native_file_read::Action,
};
use nestlink_remote::{ChannelRuntime, files::FileReadServer};
use nestlink_sdk::{
    browse::{NativeBrowseError, NativeBrowsePhase, NativeBrowseRequest, NativeDirectoryBrowse},
    files::{NativeDownloadError, NativeDownloadRequest},
};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{fs, time::Duration};
use support::*;

struct Provider {
    id: String,
    roots: BrowseRoots<FileRoots>,
    consent: BrowseConsent,
    _read_consent: Option<ReadRootConsent>,
}
fn provider(path: &std::path::Path, limits: BrowseLimits, contents: bool) -> Result<Provider> {
    let id = random_id();
    let (files, read_consent) = if contents {
        let (root, consent) = ApprovedReadRoot::open(&id, path, FILE_SIZE_BYTES)?;
        (FileRoots::new(vec![root])?, Some(consent))
    } else {
        (FileRoots::new(Vec::new())?, None)
    };
    let (selection, consent) = BrowseSelection::new(&id, path, limits)?;
    Ok(Provider {
        id,
        roots: BrowseRoots::new(files, vec![selection])?,
        consent,
        _read_consent: read_consent,
    })
}
async fn viewing(s: &mut Sessions) -> Result {
    s.h.send(Channel::Video, b"approved viewing").await?;
    let frame = tokio::time::timeout(Duration::from_secs(1), s.c.receive()).await??;
    assert_eq!(
        (frame.channel, frame.payload.as_slice()),
        (Channel::Video, &b"approved viewing"[..])
    );
    Ok(())
}
async fn receive(host: &mut ChannelRuntime) -> Result<NativeFileRead> {
    let frame = tokio::time::timeout(Duration::from_secs(2), host.receive()).await??;
    assert_eq!(frame.channel, Channel::FileRead);
    Ok(NativeFileRead::decode_validated(&frame.payload)?)
}
fn wire_page(root: &str, offset: u32, total: u32) -> DirectoryBrowsePage {
    DirectoryBrowsePage {
        root_id: root.into(),
        directory: String::new(),
        snapshot_id: vec![9; 32],
        offset,
        total_entries: total,
        entries: vec![DirectoryEntry {
            name: char::from_u32(u32::from(b'a') + offset)
                .unwrap_or('z')
                .to_string(),
            kind: DirectoryEntryKind::DirectoryEntryFile as i32,
            size: Some(1),
            modified_unix_ms: -1,
        }],
        next_cursor: if offset + 1 < total {
            vec![77 + offset as u8; 32]
        } else {
            Vec::new()
        },
    }
}
async fn reply_page(
    host: &mut ChannelRuntime,
    mut request: NativeFileRead,
    root: &str,
    offset: u32,
    total: u32,
) -> Result {
    request.action = Some(Action::BrowsePage(wire_page(root, offset, total)));
    host.send(Channel::FileRead, &request.encode_validated()?)
        .await?;
    Ok(())
}
async fn reply_cancel(host: &mut ChannelRuntime, mut request: NativeFileRead) -> Result {
    assert_eq!(request.action, Some(Action::Cancel(true)));
    request.action = Some(Action::Cancelled(true));
    host.send(Channel::FileRead, &request.encode_validated()?)
        .await?;
    Ok(())
}
async fn manual_begin(
    s: &mut Sessions,
    request: NativeBrowseRequest,
    total: u32,
) -> Result<NativeDirectoryBrowse> {
    let root = request.root_id().to_string();
    let mut browse = NativeDirectoryBrowse::attach(&mut s.c, 9, request)?;
    let first = receive(&mut s.h).await?;
    assert_eq!(first.sequence, 1);
    assert!(matches!(first.action, Some(Action::BrowseBegin(_))));
    reply_page(&mut s.h, first, &root, 0, total).await?;
    let page = browse.ready().await?;
    assert_eq!((page.offset, page.entries[0].name.as_str()), (0, "a"));
    Ok(browse)
}

#[tokio::test]
async fn sdk_tls_and_quic_pages_reuse_the_claim_for_refresh_and_verified_downloads() -> Result {
    for quic in [false, true] {
        let source = TempDirectory::new()?;
        let output = TempDirectory::new()?;
        fs::create_dir(source.path().join("nested"))?;
        fs::write(source.path().join("nested/中文.txt"), b"child")?;
        for i in (0..139).rev() {
            fs::write(source.path().join(format!("item-{i:03}")), b"x")?;
        }
        let p = provider(source.path(), BrowseLimits::default(), true)?;
        let mut s = Sessions::new(quic).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, p.roots)?;
        let mut browse = NativeDirectoryBrowse::attach(
            &mut s.c,
            9,
            NativeBrowseRequest::new(&p.id, None, 128)?,
        )?;
        let first = browse.ready().await?;
        assert_eq!(
            (
                first.offset,
                first.total_entries,
                first.entries.len(),
                first.has_more
            ),
            (0, 140, 128, true)
        );
        let last = browse.next_page(128).await?.ok_or("missing final page")?;
        assert_eq!(
            (last.offset, last.entries.len(), last.has_more),
            (128, 12, false)
        );
        assert_eq!(first.snapshot_id, last.snapshot_id);
        let mut entries = first.entries;
        entries.extend(last.entries);
        assert!(entries.windows(2).all(|p| p[0].name < p[1].name));
        let nested = entries.last().ok_or("missing child directory")?;
        assert_eq!(
            (nested.name.as_str(), nested.kind, nested.size),
            (
                "nested",
                DirectoryEntryKind::DirectoryEntryDirectory as i32,
                None
            )
        );
        assert!(browse.next_page(1).await?.is_none());
        assert_eq!(browse.status().pages_delivered, 2);
        let client = browse.take_client().await?;
        let mut child = client.begin(NativeBrowseRequest::new(&p.id, Some("nested"), 128)?)?;
        let page = child.ready().await?;
        assert_eq!(
            (
                page.entries[0].name.as_str(),
                page.entries[0].size,
                page.has_more
            ),
            ("中文.txt", Some(5), false)
        );
        assert_ne!(page.snapshot_id, first.snapshot_id);
        let (selection, _save_keep) =
            LocalDownloadSelection::new(&output.path().join("saved"), "chosen", FILE_SIZE_BYTES)?;
        let mut download = child.take_client().await?.start_download(
            NativeDownloadRequest::new(&p.id, "nested/中文.txt")?,
            selection,
        )?;
        download.download_to_end().await?;
        assert_eq!(fs::read(output.path().join("saved/chosen"))?, b"child");
        download.release_client().await?;
        viewing(&mut s).await?;
        server.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sdk_mutation_and_metadata_revocation_allow_fresh_browse_and_independent_download() -> Result
{
    let source = TempDirectory::new()?;
    let output = TempDirectory::new()?;
    fs::write(source.path().join("a"), b"a")?;
    fs::write(source.path().join("b"), b"b")?;
    let p = provider(source.path(), BrowseLimits::default(), true)?;
    let mut s = Sessions::new(false).await?;
    let mut server = FileReadServer::start(&mut s.h, 9, p.roots)?;
    let mut browse =
        NativeDirectoryBrowse::attach(&mut s.c, 9, NativeBrowseRequest::new(&p.id, None, 1)?)?;
    browse.ready().await?;
    fs::write(source.path().join("c"), b"c")?;
    assert_eq!(
        browse.next_page(1).await,
        Err(NativeBrowseError::Source(
            FileReadErrorCode::FileReadChanged
        ))
    );
    let mut fresh = browse
        .take_client()
        .await?
        .begin(NativeBrowseRequest::new(&p.id, None, 1)?)?;
    assert_eq!(fresh.ready().await?.total_entries, 3);
    assert_ne!(browse.status().transfer_id, fresh.status().transfer_id);
    p.consent.revoke();
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert_eq!(
        fresh.next_page(1).await,
        Err(NativeBrowseError::Source(FileReadErrorCode::FileReadDenied))
    );
    let (selection, _save_keep) =
        LocalDownloadSelection::new(&output.path().join("saved"), "chosen", 1)?;
    let mut download = fresh
        .take_client()
        .await?
        .start_download(NativeDownloadRequest::new(&p.id, "a")?, selection)?;
    download.download_to_end().await?;
    download.release_client().await?;
    assert_eq!(fs::read(output.path().join("saved/chosen"))?, b"a");
    viewing(&mut s).await?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn sdk_remote_snapshot_expiry_and_metadata_only_roots_keep_view_permission() -> Result {
    for expired in [false, true] {
        let source = TempDirectory::new()?;
        let output = TempDirectory::new()?;
        fs::write(source.path().join("a"), b"a")?;
        fs::write(source.path().join("b"), b"b")?;
        let limits = if expired {
            BrowseLimits::new(
                4096,
                1048576,
                Duration::from_secs(1),
                Duration::from_millis(80),
            )?
        } else {
            BrowseLimits::default()
        };
        let p = provider(source.path(), limits, false)?;
        let mut s = Sessions::new(true).await?;
        let mut server = FileReadServer::start(&mut s.h, 9, p.roots)?;
        let mut browse = NativeDirectoryBrowse::attach(
            &mut s.c,
            9,
            NativeBrowseRequest::new(&p.id, None, if expired { 1 } else { 128 })?,
        )?;
        browse.ready().await?;
        if expired {
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert_eq!(
                browse.next_page(1).await,
                Err(NativeBrowseError::Source(
                    FileReadErrorCode::FileReadChanged
                ))
            );
            browse.release_client().await?;
        } else {
            let area = output.path().join("denied");
            let (selection, _keep) = LocalDownloadSelection::new(&area, "chosen", 1)?;
            let mut download = browse
                .take_client()
                .await?
                .start_download(NativeDownloadRequest::new(&p.id, "a")?, selection)?;
            assert_eq!(
                download.ready().await,
                Err(NativeDownloadError::Source(
                    FileReadErrorCode::FileReadDenied
                ))
            );
            download.release_client().await?;
            assert!(!area.exists());
        }
        viewing(&mut s).await?;
        server.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sdk_invalid_local_requests_do_not_consume_claim_or_live_cursor() -> Result {
    let id = random_id();
    for (root, path, maximum) in [
        ("bad", None, 1),
        (id.as_str(), Some("../escape"), 1),
        (id.as_str(), Some(""), 0),
        (id.as_str(), None, 129),
    ] {
        assert!(NativeBrowseRequest::new(root, path, maximum).is_err());
    }
    assert!(
        NativeBrowseRequest::new(&id, None, 1)?
            .with_budgets(Duration::ZERO, Duration::from_secs(1))
            .is_err()
    );
    assert!(
        NativeBrowseRequest::new(&id, None, 1)?
            .with_budgets(
                Duration::from_millis(FILE_OPERATION_MS + 1),
                Duration::from_secs(1)
            )
            .is_err()
    );
    assert!(
        NativeBrowseRequest::new(&id, None, 1)?
            .with_budgets(
                Duration::from_secs(1),
                Duration::from_millis(DIRECTORY_SNAPSHOT_MS + 1)
            )
            .is_err()
    );
    let source = TempDirectory::new()?;
    fs::write(source.path().join("a"), b"a")?;
    fs::write(source.path().join("b"), b"b")?;
    let p = provider(source.path(), BrowseLimits::default(), false)?;
    let mut s = Sessions::new(false).await?;
    assert!(
        NativeDirectoryBrowse::attach(&mut s.c, 10, NativeBrowseRequest::new(&p.id, None, 1)?)
            .is_err()
    );
    let mut server = FileReadServer::start(&mut s.h, 9, p.roots)?;
    let mut browse =
        NativeDirectoryBrowse::attach(&mut s.c, 9, NativeBrowseRequest::new(&p.id, None, 1)?)?;
    assert!(matches!(
        browse.next_page(1).await,
        Err(NativeBrowseError::State(_))
    ));
    browse.ready().await?;
    assert!(matches!(
        browse.ready().await,
        Err(NativeBrowseError::State(_))
    ));
    for maximum in [0, 129] {
        assert!(matches!(
            browse.next_page(maximum).await,
            Err(NativeBrowseError::State(_))
        ));
    }
    assert_eq!(
        browse
            .next_page(1)
            .await?
            .ok_or("missing valid successor")?
            .entries[0]
            .name,
        "b"
    );
    assert_eq!(browse.status().pages_received, 2);
    browse.release_client().await?;
    viewing(&mut s).await?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn sdk_concurrent_and_abandoned_page_waits_drain_exact_rpc_then_cancel_before_reuse() -> Result
{
    for quic in [false, true] {
        let mut s = Sessions::new(quic).await?;
        let id = random_id();
        let mut browse = manual_begin(&mut s, NativeBrowseRequest::new(&id, None, 1)?, 3).await?;
        let mut next = Box::pin(browse.next_page(1));
        let request = tokio::select! {
            result = &mut next => return Err(format!("unexpected early page: {result:?}").into()),
            request = receive(&mut s.h) => request?,
        };
        assert_eq!(request.sequence, 2);
        assert!(
            matches!(&request.action, Some(Action::BrowseNext(next)) if next.cursor == vec![77; 32])
        );
        assert!(matches!(
            browse.next_page(1).await,
            Err(NativeBrowseError::State(_))
        ));
        drop(next);
        assert_eq!(browse.next_page(1).await, Err(NativeBrowseError::Cancelled));
        reply_page(&mut s.h, request, &id, 1, 3).await?;
        let cancel = receive(&mut s.h).await?;
        assert_eq!(
            (cancel.sequence, cancel.transfer_id.as_str()),
            (3, browse.status().transfer_id.as_str())
        );
        assert!(browse.status().source_request_pending);
        let pending_return =
            tokio::time::timeout(Duration::from_millis(20), browse.take_client()).await;
        assert!(
            pending_return.is_err(),
            "no claimant can return before exact Cancel acknowledgement"
        );
        reply_cancel(&mut s.h, cancel).await?;
        let status = browse.monitor().wait_finished().await;
        assert_eq!(
            (status.phase, status.pages_received, status.pages_delivered),
            (NativeBrowsePhase::Cancelled, 2, 1)
        );
        assert!(status.source_closed && status.source_cancel_acknowledged);
        let mut fresh = browse
            .take_client()
            .await?
            .begin(NativeBrowseRequest::new(&id, None, 1)?)?;
        let first = receive(&mut s.h).await?;
        assert_eq!(first.sequence, 4);
        assert_ne!(first.transfer_id, status.transfer_id);
        reply_page(&mut s.h, first, &id, 0, 1).await?;
        assert!(!fresh.ready().await?.has_more);
        fresh.release_client().await?;
        viewing(&mut s).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sdk_cancel_during_initial_begin_suppresses_page_and_consumes_begin_before_cancel() -> Result
{
    let mut s = Sessions::new(false).await?;
    let id = random_id();
    let mut browse =
        NativeDirectoryBrowse::attach(&mut s.c, 9, NativeBrowseRequest::new(&id, None, 1)?)?;
    let first = receive(&mut s.h).await?;
    let local = browse.cancel();
    assert!(
        local.delivery_stopped && local.source_request_pending && !local.source_cancel_acknowledged
    );
    assert_eq!(browse.ready().await, Err(NativeBrowseError::Cancelled));
    reply_page(&mut s.h, first, &id, 0, 2).await?;
    let cancel = receive(&mut s.h).await?;
    assert_eq!(cancel.sequence, 2);
    reply_cancel(&mut s.h, cancel).await?;
    let status = browse.monitor().wait_finished().await;
    assert_eq!((status.pages_received, status.pages_delivered), (1, 0));
    assert!(status.source_closed && status.source_cancel_acknowledged);
    browse.release_client().await?;
    viewing(&mut s).await?;
    Ok(())
}

#[tokio::test]
async fn sdk_original_operation_budget_covers_retained_first_page_and_late_continuation() -> Result
{
    for retained in [true, false] {
        let mut s = Sessions::new(false).await?;
        let id = random_id();
        let request = NativeBrowseRequest::new(&id, None, 1)?
            .with_budgets(Duration::from_millis(150), Duration::from_secs(2))?;
        let mut browse = NativeDirectoryBrowse::attach(&mut s.c, 9, request)?;
        let first = receive(&mut s.h).await?;
        reply_page(&mut s.h, first, &id, 0, 3).await?;
        if retained {
            // The actor completes on time, but the SDK caller consumes too late.
            tokio::time::sleep(Duration::from_millis(220)).await;
            assert_eq!(browse.ready().await, Err(NativeBrowseError::Expired));
        } else {
            browse.ready().await?;
            let mut next = Box::pin(browse.next_page(1));
            let request = tokio::select! {
                result = &mut next => return Err(format!("unexpected early page: {result:?}").into()),
                request = receive(&mut s.h) => request?,
            };
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), &mut next).await?,
                Err(NativeBrowseError::Expired)
            );
            drop(next);
            assert!(browse.status().source_request_pending);
            reply_page(&mut s.h, request, &id, 1, 3).await?;
        }
        let cancel = receive(&mut s.h).await?;
        assert_eq!(cancel.sequence, if retained { 2 } else { 3 });
        reply_cancel(&mut s.h, cancel).await?;
        let status = browse.monitor().wait_finished().await;
        assert_eq!(status.pages_delivered, if retained { 0 } else { 1 });
        assert_eq!(status.error, Some(NativeBrowseError::Expired));
        assert!(status.source_cancel_acknowledged && status.source_closed);
        browse.release_client().await?;
        viewing(&mut s).await?;
    }
    Ok(())
}

#[tokio::test]
async fn sdk_snapshot_lifetime_is_fixed_across_successful_page_progress() -> Result {
    let mut s = Sessions::new(false).await?;
    let id = random_id();
    let request = NativeBrowseRequest::new(&id, None, 1)?
        .with_budgets(Duration::from_secs(2), Duration::from_millis(700))?;
    let mut browse = manual_begin(&mut s, request, 3).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let peer = async {
        let request = receive(&mut s.h).await?;
        reply_page(&mut s.h, request, &id, 1, 3).await
    };
    let (page, peer) = tokio::join!(browse.next_page(1), peer);
    assert_eq!(page?.ok_or("missing middle page")?.offset, 1);
    peer?;
    tokio::time::sleep(Duration::from_millis(450)).await;
    let cancel = receive(&mut s.h).await?;
    assert_eq!(
        cancel.sequence, 3,
        "progress cannot move the original expiry from 700 to 1000 ms"
    );
    assert_eq!(browse.next_page(1).await, Err(NativeBrowseError::Expired));
    reply_cancel(&mut s.h, cancel).await?;
    browse.release_client().await?;
    viewing(&mut s).await?;
    Ok(())
}

#[tokio::test]
async fn sdk_session_stop_suppresses_pages_and_unknown_cleanup_preserves_network_recovery() -> Result
{
    for reason in [StopReason::NetworkChanged, StopReason::Revoked] {
        let mut s = Sessions::new(false).await?;
        let id = random_id();
        let mut browse = manual_begin(&mut s, NativeBrowseRequest::new(&id, None, 1)?, 3).await?;
        let mut next = Box::pin(browse.next_page(1));
        let request = tokio::select! {
            result = &mut next => return Err(format!("unexpected early page: {result:?}").into()),
            request = receive(&mut s.h) => request?,
        };
        assert_eq!(request.sequence, 2);
        let lease = s.c.lease_control();
        lease.stop(reason)?;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), &mut next)
                .await?
                .is_err()
        );
        drop(next);
        let status =
            tokio::time::timeout(Duration::from_secs(1), browse.monitor().wait_finished()).await?;
        assert_eq!(status.pages_delivered, 1);
        assert!(!status.source_closed && !status.source_cancel_acknowledged);
        assert!(browse.release_client().await.is_err());
        if reason == StopReason::NetworkChanged {
            assert!(
                lease.reconnection_budget().is_ok(),
                "unknown cleanup retirement must not invent a protocol failure"
            );
            let mut fresh = Sessions::with_scope(true, Some(&s.scope), 10).await?;
            let mut new_browse = NativeDirectoryBrowse::attach(
                &mut fresh.c,
                10,
                NativeBrowseRequest::new(&id, None, 1)?,
            )?;
            let first = receive(&mut fresh.h).await?;
            assert_eq!((first.sequence, first.connection_generation), (1, 10));
            reply_page(&mut fresh.h, first, &id, 0, 1).await?;
            assert_eq!(new_browse.ready().await?.offset, 0);
            new_browse.release_client().await?;
            viewing(&mut fresh).await?;
        } else {
            assert!(lease.reconnection_budget().is_err());
        }
    }
    Ok(())
}

#[tokio::test]
async fn sdk_peer_cannot_substitute_a_snapshot_before_application_delivery() -> Result {
    let mut s = Sessions::new(true).await?;
    let id = random_id();
    let mut browse = manual_begin(&mut s, NativeBrowseRequest::new(&id, None, 1)?, 3).await?;
    let mut next = Box::pin(browse.next_page(1));
    let mut request = tokio::select! {
        result = &mut next => return Err(format!("unexpected early page: {result:?}").into()),
        request = receive(&mut s.h) => request?,
    };
    let mut altered = wire_page(&id, 1, 3);
    altered.snapshot_id = vec![10; 32];
    request.action = Some(Action::BrowsePage(altered));
    s.h.send(Channel::FileRead, &request.encode_validated()?)
        .await?;
    assert!(next.await.is_err());
    let status = browse.monitor().wait_finished().await;
    assert_eq!(status.pages_delivered, 1);
    assert!(!status.source_closed);
    assert!(browse.release_client().await.is_err());
    assert!(s.c.lease_control().reconnection_budget().is_err());
    Ok(())
}
