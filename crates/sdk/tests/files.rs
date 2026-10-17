#![cfg(not(target_arch = "wasm32"))]
#[path = "files/blocked.rs"]
mod blocked;
#[path = "files/pause_barriers.rs"]
mod pause_barriers;
#[path = "files/support.rs"]
mod support;
#[path = "files/worker_lifecycle.rs"]
mod worker_lifecycle;
use nestlink_auth::random_id;
use nestlink_identity::digest;
use nestlink_platform_files::{
    ApprovedReadRoot, FileRoots, ReadRootConsent, download::LocalDownloadSelection,
};
use nestlink_protocol::{
    FILE_SIZE_BYTES, FileReadChunk, FileReadErrorCode, FileReadManifest, NativeFileRead,
    native_file_read::Action,
};
use nestlink_remote::files::{FileReadClient, FileReadServer, FileShutdown};
use nestlink_sdk::files::{
    NativeDownloadError, NativeDownloadPhase, NativeDownloadRequest, NativeFileDownload,
};
use nestlink_session::StopReason;
use nestlink_transport_stream::Channel;
use std::{fs, time::Duration};
use support::*;

fn roots(path: &std::path::Path, id: &str) -> Result<(FileRoots, ReadRootConsent)> {
    let (root, consent) = ApprovedReadRoot::open(id, path, FILE_SIZE_BYTES)?;
    Ok((FileRoots::new(vec![root])?, consent))
}

#[tokio::test]
async fn sdk_downloads_tls_and_quic_files_with_progress_and_explicit_verified_publication() -> Result
{
    for quic in [false, true] {
        for empty in [false, true] {
            let source = TempDirectory::new()?;
            let output = TempDirectory::new()?;
            let bytes: Vec<_> = (0..if empty { 0 } else { 180 * 1024 + 73 })
                .map(|i| (i % 251) as u8)
                .collect();
            fs::write(source.path().join("source"), &bytes)?;
            let root = random_id();
            let (provider, _keep) = roots(source.path(), &root)?;
            let mut sessions = Sessions::new(quic).await?;
            let mut server = FileReadServer::start(&mut sessions.h, 9, provider)?;
            let area = output.path().join("download");
            let (selection, _save_consent) =
                LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
            let request = NativeDownloadRequest::new(&root, "source")?;
            let mut download = NativeFileDownload::attach(&mut sessions.c, 9, request, selection)?;
            let monitor = download.monitor();
            let ready = download.ready().await?;
            assert_eq!(ready.phase, NativeDownloadPhase::Ready);
            assert_eq!(
                ready.manifest.as_ref().ok_or("missing manifest")?.sha256,
                digest(&bytes)
            );
            let mut saved = 0;
            while !download.status().source_verified {
                let status = download.pull().await?;
                let disk = status.destination.ok_or("missing disk status")?.destination;
                assert!(disk.confirmed_bytes >= saved);
                assert_eq!(disk.confirmed_bytes, status.received_bytes);
                saved = disk.confirmed_bytes;
                assert!(!disk.published && !area.join("done").exists());
            }
            let completed = download.finish().await?;
            assert_eq!(completed.phase, NativeDownloadPhase::Completed);
            assert!(completed.source_verified && completed.local_stopped);
            assert_eq!(completed.destination_shutdown, Some(FileShutdown::Finished));
            let actual = monitor.wait_finished().await;
            assert!(actual.actor_finished);
            let disk = actual.destination.ok_or("missing completed disk")?;
            assert!(
                disk.finished
                    && disk.destination.published
                    && disk.destination.file_closed
                    && disk.destination.temporary_removed
                    && !disk.destination.poisoned
            );
            assert_eq!(fs::read(area.join("done"))?, bytes);
            let retired = download.release_client().await?;
            assert_eq!(retired.client_retirement, Some(Ok(())));
            sessions
                .c
                .lease_control()
                .check_channel_binding(Channel::Video, 9)?;
            server.shutdown(StopReason::ExplicitExit).await?;
        }
    }
    Ok(())
}

async fn reply_manifest(host: &mut nestlink_remote::ChannelRuntime, data: &[u8]) -> Result {
    let received = host.receive().await?;
    let mut reply = NativeFileRead::decode_validated(&received.payload)?;
    assert!(matches!(reply.action, Some(Action::Open(_))));
    reply.action = Some(Action::Manifest(FileReadManifest {
        size: data.len() as u64,
        sha256: digest(data).to_vec(),
        offset: 0,
    }));
    host.send(Channel::FileRead, &reply.encode_validated()?)
        .await?;
    Ok(())
}

#[tokio::test]
async fn sdk_cancel_stops_destination_before_a_slow_source_reply_and_consumes_the_original_rpc()
-> Result {
    let output = TempDirectory::new()?;
    let mut sessions = Sessions::new(false).await?;
    let root = random_id();
    let area = output.path().join("cancelled");
    let (selection, _consent) = LocalDownloadSelection::new(&area, "done", 4)?;
    let mut download = NativeFileDownload::attach(
        &mut sessions.c,
        9,
        NativeDownloadRequest::new(&root, "source")?,
        selection,
    )?;
    let (ready, peer) = tokio::join!(download.ready(), reply_manifest(&mut sessions.h, b"data"));
    ready?;
    peer?;
    let mut pull = Box::pin(download.pull());
    let request = tokio::select! {
        result = &mut pull => return Err(format!("pull completed without a peer response: {result:?}").into()),
        request = sessions.h.receive() => request?,
    };
    drop(pull);
    assert!(
        matches!(download.pull().await, Err(NativeDownloadError::State(_))),
        "an abandoned await cannot be replaced by another RPC"
    );
    sessions
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    let cancelled = tokio::time::timeout(Duration::from_secs(1), download.cancel()).await?;
    assert!(
        cancelled.local_stopped
            && cancelled.source_request_pending
            && !cancelled.source_cancel_acknowledged
    );
    let destination = cancelled
        .destination
        .ok_or("missing cancelled destination")?;
    assert!(
        destination.finished
            && destination.destination.file_closed
            && destination.destination.temporary_removed
    );
    assert!(!destination.destination.published);
    sessions
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    let mut reply = NativeFileRead::decode_validated(&request.payload)?;
    assert!(matches!(reply.action, Some(Action::Next(_))));
    reply.action = Some(Action::Chunk(FileReadChunk {
        offset: 0,
        data: b"data".to_vec(),
        sha256: digest(b"data").to_vec(),
    }));
    sessions
        .h
        .send(Channel::FileRead, &reply.encode_validated()?)
        .await?;
    let cancel = sessions.h.receive().await?;
    let mut cancel = NativeFileRead::decode_validated(&cancel.payload)?;
    assert_eq!(cancel.action, Some(Action::Cancel(true)));
    cancel.action = Some(Action::Cancelled(true));
    sessions
        .h
        .send(Channel::FileRead, &cancel.encode_validated()?)
        .await?;
    let final_status =
        tokio::time::timeout(Duration::from_secs(1), download.monitor().wait_finished()).await?;
    assert_eq!(final_status.phase, NativeDownloadPhase::Cancelled);
    assert_eq!(final_status.received_bytes, 4);
    assert!(final_status.source_cancel_requested && final_status.source_cancel_acknowledged);
    assert_eq!(
        final_status
            .destination
            .ok_or("missing final destination")?
            .destination
            .confirmed_bytes,
        0
    );
    assert!(!area.join("done").exists());
    let monitor = download.monitor();
    drop(download);
    assert_eq!(monitor.status().client_retirement, Some(Ok(())));
    sessions
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    Ok(())
}

#[tokio::test]
async fn sdk_pause_resumes_actual_prefix_on_same_or_freshly_proved_matching_connection() -> Result {
    let source = TempDirectory::new()?;
    let output = TempDirectory::new()?;
    let bytes: Vec<_> = (0..250 * 1024 + 37).map(|i| (i % 239) as u8).collect();
    fs::write(source.path().join("source"), &bytes)?;
    let root = random_id();
    let (provider, _keep) = roots(source.path(), &root)?;
    let mut sessions = Sessions::new(true).await?;
    let mut server = FileReadServer::start(&mut sessions.h, 9, provider)?;
    let area = output.path().join("resumed");
    let (selection, _save_keep) = LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
    let mut download = NativeFileDownload::attach(
        &mut sessions.c,
        9,
        NativeDownloadRequest::new(&root, "source")?,
        selection,
    )?;
    download.ready().await?;
    let first = download
        .pull()
        .await?
        .destination
        .ok_or("missing first disk")?
        .destination
        .confirmed_bytes;
    assert!(first > 0);
    let paused = download.pause().await?;
    assert!(paused.source_cancel_acknowledged);
    assert_eq!(
        paused
            .destination
            .ok_or("missing paused disk")?
            .destination
            .confirmed_bytes,
        first
    );
    assert!(matches!(
        download.pull().await,
        Err(NativeDownloadError::State(_))
    ));
    download.resume(None).await?;
    let second = download
        .pull()
        .await?
        .destination
        .ok_or("missing second disk")?
        .destination
        .confirmed_bytes;
    assert!(second > first);
    download.pause().await?;
    sessions
        .c
        .lease_control()
        .stop(StopReason::NetworkChanged)?;
    server.shutdown(StopReason::NetworkChanged).await?;
    let (provider, _next_keep) = roots(source.path(), &root)?;
    let mut next = Sessions::with_scope(false, Some(&sessions.scope), 10).await?;
    let mut next_server = FileReadServer::start(&mut next.h, 10, provider)?;
    let next_client = FileReadClient::attach(&mut next.c, 10)?;
    let resumed = download.resume(Some(next_client)).await?;
    assert_eq!(resumed.received_bytes, second);
    download.download_to_end().await?;
    assert_eq!(fs::read(area.join("done"))?, bytes);
    download.release_client().await?;
    next.c
        .lease_control()
        .check_channel_binding(Channel::Video, 10)?;
    next_server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn sdk_rejects_another_proved_resource_without_losing_the_paused_partial() -> Result {
    let source = TempDirectory::new()?;
    let output = TempDirectory::new()?;
    let bytes = vec![73; 140 * 1024];
    fs::write(source.path().join("source"), &bytes)?;
    let root = random_id();
    let (provider, _keep) = roots(source.path(), &root)?;
    let mut original = Sessions::new(false).await?;
    let mut server = FileReadServer::start(&mut original.h, 9, provider)?;
    let area = output.path().join("scope");
    let (selection, _save_keep) = LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
    let mut download = NativeFileDownload::attach(
        &mut original.c,
        9,
        NativeDownloadRequest::new(&root, "source")?,
        selection,
    )?;
    download.ready().await?;
    let confirmed = download
        .pull()
        .await?
        .destination
        .ok_or("missing prefix")?
        .destination
        .confirmed_bytes;
    download.pause().await?;
    let (provider, _wrong_keep) = roots(source.path(), &root)?;
    let mut wrong = Sessions::with_scope(true, None, 10).await?;
    let mut wrong_server = FileReadServer::start(&mut wrong.h, 10, provider)?;
    assert!(matches!(
        download
            .resume(Some(FileReadClient::attach(&mut wrong.c, 10)?))
            .await,
        Err(NativeDownloadError::Destination(
            std::io::ErrorKind::PermissionDenied
        ))
    ));
    assert_eq!(download.status().phase, NativeDownloadPhase::Paused);
    assert_eq!(
        download
            .status()
            .destination
            .ok_or("missing retained disk")?
            .destination
            .confirmed_bytes,
        confirmed
    );
    wrong
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 10)?;
    download.resume(None).await?;
    download.download_to_end().await?;
    assert_eq!(fs::read(area.join("done"))?, bytes);
    download.release_client().await?;
    original
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    server.shutdown(StopReason::ExplicitExit).await?;
    wrong_server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn sdk_returned_client_reuses_its_claim_and_exact_sequence_for_another_download() -> Result {
    let source = TempDirectory::new()?;
    let output = TempDirectory::new()?;
    fs::write(source.path().join("first"), b"first bytes")?;
    fs::write(source.path().join("second"), b"second bytes")?;
    let root = random_id();
    let (provider, _keep) = roots(source.path(), &root)?;
    let mut sessions = Sessions::new(false).await?;
    let mut server = FileReadServer::start(&mut sessions.h, 9, provider)?;
    let (selection, _first_consent) =
        LocalDownloadSelection::new(&output.path().join("first"), "done", FILE_SIZE_BYTES)?;
    let mut first = NativeFileDownload::attach(
        &mut sessions.c,
        9,
        NativeDownloadRequest::new(&root, "first")?,
        selection,
    )?;
    first.download_to_end().await?;
    let first_monitor = first.monitor();
    let client = first.take_client().await?;
    assert!(matches!(
        first.take_client().await,
        Err(NativeDownloadError::State(_))
    ));
    drop(first);
    let (selection, _second_consent) =
        LocalDownloadSelection::new(&output.path().join("second"), "done", FILE_SIZE_BYTES)?;
    let mut second = client.start(NativeDownloadRequest::new(&root, "second")?, selection)?;
    second.download_to_end().await?;
    let retired = second.release_client().await?;
    assert_eq!(retired.client_retirement, Some(Ok(())));
    assert_eq!(
        first_monitor.status().client_retirement,
        None,
        "the original client was reused, not retired"
    );
    assert_eq!(fs::read(output.path().join("first/done"))?, b"first bytes");
    assert_eq!(
        fs::read(output.path().join("second/done"))?,
        b"second bytes"
    );
    sessions
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}

#[tokio::test]
async fn sdk_cancel_during_initial_open_creates_no_local_area_and_consumes_open_then_cancel()
-> Result {
    let output = TempDirectory::new()?;
    let mut sessions = Sessions::new(false).await?;
    let area = output.path().join("never-opened");
    let (selection, _consent) = LocalDownloadSelection::new(&area, "done", 4)?;
    let mut download = NativeFileDownload::attach(
        &mut sessions.c,
        9,
        NativeDownloadRequest::new(&random_id(), "source")?,
        selection,
    )?;
    let request = sessions.h.receive().await?;
    let mut reply = NativeFileRead::decode_validated(&request.payload)?;
    assert!(matches!(reply.action, Some(Action::Open(_))));
    let local = tokio::time::timeout(Duration::from_secs(1), download.cancel()).await?;
    assert!(local.local_stopped && local.source_request_pending && local.destination.is_none());
    assert!(!area.exists());
    reply.action = Some(Action::Manifest(FileReadManifest {
        size: 4,
        sha256: digest(b"data").to_vec(),
        offset: 0,
    }));
    sessions
        .h
        .send(Channel::FileRead, &reply.encode_validated()?)
        .await?;
    let cancel = sessions.h.receive().await?;
    let mut cancel = NativeFileRead::decode_validated(&cancel.payload)?;
    assert_eq!(cancel.action, Some(Action::Cancel(true)));
    cancel.action = Some(Action::Cancelled(true));
    sessions
        .h
        .send(Channel::FileRead, &cancel.encode_validated()?)
        .await?;
    let retired = download.release_client().await?;
    assert_eq!(retired.client_retirement, Some(Ok(())));
    assert!(retired.source_attempts[0].cancel_acknowledged);
    assert!(!area.exists());
    sessions
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    Ok(())
}

#[tokio::test]
async fn sdk_idle_local_consent_revocation_and_missing_source_preserve_viewing() -> Result {
    for missing in [false, true] {
        let source = TempDirectory::new()?;
        let output = TempDirectory::new()?;
        fs::write(source.path().join("source"), b"file data")?;
        let root = random_id();
        let (provider, _keep) = roots(source.path(), &root)?;
        let mut sessions = Sessions::new(false).await?;
        let mut server = FileReadServer::start(&mut sessions.h, 9, provider)?;
        let area = output.path().join("revoked");
        let (selection, consent) = LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
        let mut download = NativeFileDownload::attach(
            &mut sessions.c,
            9,
            NativeDownloadRequest::new(&root, if missing { "absent" } else { "source" })?,
            selection,
        )?;
        if missing {
            assert_eq!(
                download.ready().await,
                Err(NativeDownloadError::Source(
                    FileReadErrorCode::FileReadNotFound
                ))
            );
        } else {
            download.ready().await?;
            consent.revoke();
        }
        let actual =
            tokio::time::timeout(Duration::from_secs(2), download.monitor().wait_finished())
                .await?;
        assert_eq!(actual.phase, NativeDownloadPhase::Failed);
        if missing {
            assert!(actual.destination.is_none() && !area.exists());
        } else {
            assert!(
                actual
                    .destination
                    .ok_or("missing revoked destination")?
                    .finished
            );
            assert!(actual.source_cancel_acknowledged);
        }
        assert!(!area.join("done").exists());
        download.release_client().await?;
        sessions
            .c
            .lease_control()
            .check_channel_binding(Channel::Video, 9)?;
        server.shutdown(StopReason::ExplicitExit).await?;
    }
    Ok(())
}
