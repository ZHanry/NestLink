use super::*;
use std::{
    future::Future,
    task::{Context, Poll, Waker},
};

async fn cancel_reply(host: &mut nestlink_remote::ChannelRuntime) -> Result {
    let received = host.receive().await?;
    let mut reply = NativeFileRead::decode_validated(&received.payload)?;
    assert_eq!(reply.action, Some(Action::Cancel(true)));
    reply.action = Some(Action::Cancelled(true));
    host.send(Channel::FileRead, &reply.encode_validated()?)
        .await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn new_pause_waits_for_abandoned_resume_open_and_exact_candidate_cancel() -> Result {
    let output = TempDirectory::new()?;
    let mut sessions = Sessions::new(false).await?;
    let root = random_id();
    let (selection, _consent) =
        LocalDownloadSelection::new(&output.path().join("barrier"), "done", 4)?;
    let mut download = NativeFileDownload::attach(
        &mut sessions.c,
        9,
        NativeDownloadRequest::new(&root, "source")?,
        selection,
    )?;
    let (ready, peer) = tokio::join!(download.ready(), reply_manifest(&mut sessions.h, b"data"));
    ready?;
    peer?;
    let (paused, peer) = tokio::join!(download.pause(), cancel_reply(&mut sessions.h));
    let previous_ack = paused?.pause_ack_revision;
    peer?;

    let mut resume = Box::pin(download.resume(None));
    let open = tokio::select! {
        result = &mut resume => return Err(format!("resume completed before Open reply: {result:?}").into()),
        open = sessions.h.receive() => open?,
    };
    drop(resume);
    let mut open = NativeFileRead::decode_validated(&open.payload)?;
    assert!(matches!(open.action, Some(Action::Open(_))));
    let monitor = download.monitor();
    let mut pause = Box::pin(download.pause());
    assert!(
        tokio::time::timeout(Duration::from_millis(40), &mut pause)
            .await
            .is_err(),
        "the old Paused phase cannot acknowledge an outstanding new Open"
    );
    assert_eq!(monitor.status().pause_ack_revision, previous_ack);
    open.action = Some(Action::Manifest(FileReadManifest {
        size: 4,
        sha256: digest(b"data").to_vec(),
        offset: 0,
    }));
    sessions
        .h
        .send(Channel::FileRead, &open.encode_validated()?)
        .await?;
    let cancelled = tokio::select! {
        result = &mut pause => return Err(format!("pause completed before candidate Cancel reply: {result:?}").into()),
        cancelled = sessions.h.receive() => cancelled?,
    };
    let mut cancelled = NativeFileRead::decode_validated(&cancelled.payload)?;
    assert_eq!(cancelled.action, Some(Action::Cancel(true)));
    assert_eq!(cancelled.transfer_id, open.transfer_id);
    assert!(
        tokio::time::timeout(Duration::from_millis(40), &mut pause)
            .await
            .is_err(),
        "candidate Cancel must be consumed before the new pause ACK"
    );
    assert_eq!(monitor.status().pause_ack_revision, previous_ack);
    cancelled.action = Some(Action::Cancelled(true));
    sessions
        .h
        .send(Channel::FileRead, &cancelled.encode_validated()?)
        .await?;
    let paused = tokio::time::timeout(Duration::from_secs(1), pause).await??;
    assert!(paused.pause_ack_revision > previous_ack);
    assert_eq!(paused.source_attempts.len(), 2);
    assert!(paused.source_attempts[1].cancel_acknowledged);
    download.cancel().await;
    download.release_client().await?;
    sessions
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn queued_resume_cannot_revive_a_pause_requested_after_submission() -> Result {
    let output = TempDirectory::new()?;
    let mut sessions = Sessions::new(false).await?;
    let root = random_id();
    let (selection, _consent) =
        LocalDownloadSelection::new(&output.path().join("queued"), "done", 4)?;
    let mut download = NativeFileDownload::attach(
        &mut sessions.c,
        9,
        NativeDownloadRequest::new(&root, "source")?,
        selection,
    )?;
    let (ready, peer) = tokio::join!(download.ready(), reply_manifest(&mut sessions.h, b"data"));
    ready?;
    peer?;
    let (paused, peer) = tokio::join!(download.pause(), cancel_reply(&mut sessions.h));
    let previous_ack = paused?.pause_ack_revision;
    peer?;
    let monitor = download.monitor();
    let mut resume = Box::pin(download.resume(None));
    // No executor yield: the command is enqueued but the actor has not run.
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(resume.as_mut().poll(&mut context), Poll::Pending));
    drop(resume);
    let paused = tokio::time::timeout(Duration::from_secs(1), download.pause()).await??;
    assert!(paused.pause_ack_revision > previous_ack);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), sessions.h.receive())
            .await
            .is_err(),
        "the stale Resume must be rejected before sending any Open"
    );
    assert_eq!(monitor.status().phase, NativeDownloadPhase::Paused);
    assert_eq!(monitor.status().source_attempts.len(), 1);
    assert_eq!(
        monitor.status().pause_ack_revision,
        paused.pause_ack_revision
    );
    download.cancel().await;
    download.release_client().await?;
    sessions
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    Ok(())
}

#[tokio::test]
async fn network_change_during_exact_source_rpc_retains_partial_for_fresh_proved_resume() -> Result
{
    let source = TempDirectory::new()?;
    let output = TempDirectory::new()?;
    let prefix = nestlink_protocol::FILE_PAYLOAD_BYTES as usize;
    let bytes: Vec<_> = (0..prefix * 2 + 19).map(|i| (i % 251) as u8).collect();
    fs::write(source.path().join("source"), &bytes)?;
    let root = random_id();
    let mut original = Sessions::new(false).await?;
    let area = output.path().join("network-partial");
    let (selection, _save_consent) = LocalDownloadSelection::new(&area, "done", FILE_SIZE_BYTES)?;
    let mut download = NativeFileDownload::attach(
        &mut original.c,
        9,
        NativeDownloadRequest::new(&root, "source")?,
        selection,
    )?;
    let (ready, peer) = tokio::join!(download.ready(), reply_manifest(&mut original.h, &bytes));
    ready?;
    peer?;
    let first_reply = async {
        let frame = original.h.receive().await?;
        let mut reply = NativeFileRead::decode_validated(&frame.payload)?;
        assert!(matches!(reply.action, Some(Action::Next(_))));
        reply.action = Some(Action::Chunk(FileReadChunk {
            offset: 0,
            data: bytes[..prefix].to_vec(),
            sha256: digest(&bytes[..prefix]).to_vec(),
        }));
        original
            .h
            .send(Channel::FileRead, &reply.encode_validated()?)
            .await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };
    let (saved, peer) = tokio::join!(download.pull(), first_reply);
    let confirmed = saved?
        .destination
        .ok_or("missing saved prefix")?
        .destination
        .confirmed_bytes;
    peer?;
    assert_eq!(confirmed, prefix as u64);
    let mut pending = Box::pin(download.pull());
    let frame = tokio::select! {
        result = &mut pending => return Err(format!("source RPC completed before test disconnect: {result:?}").into()),
        frame = original.h.receive() => frame?,
    };
    assert!(matches!(
        NativeFileRead::decode_validated(&frame.payload)?.action,
        Some(Action::Next(_))
    ));
    let lease = original.c.lease_control();
    lease.stop(StopReason::NetworkChanged)?;
    assert!(lease.check_channel_binding(Channel::FileRead, 9).is_err());
    assert!(lease.reconnection_budget().is_ok());
    let failed = tokio::time::timeout(Duration::from_secs(1), pending).await?;
    assert!(failed.is_err());
    let paused = download.status();
    assert_eq!(paused.phase, NativeDownloadPhase::Paused);
    assert!(paused.pause_ack_revision > 0);
    let disk = paused.destination.ok_or("missing retained destination")?;
    assert_eq!(disk.destination.confirmed_bytes, confirmed);
    assert!(!disk.finished && !disk.destination.temporary_removed && !disk.destination.published);
    assert!(
        lease.reconnection_budget().is_ok(),
        "a derived stopped RPC error must not become a new protocol violation"
    );
    let (provider, _read_consent) = roots(source.path(), &root)?;
    let mut fresh = Sessions::with_scope(true, Some(&original.scope), 10).await?;
    let mut server = FileReadServer::start(&mut fresh.h, 10, provider)?;
    let resumed = download
        .resume(Some(FileReadClient::attach(&mut fresh.c, 10)?))
        .await?;
    assert_eq!(resumed.received_bytes, confirmed);
    assert_eq!(resumed.phase, NativeDownloadPhase::Ready);
    download.download_to_end().await?;
    assert_eq!(fs::read(area.join("done"))?, bytes);
    download.release_client().await?;
    fresh
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 10)?;
    server.shutdown(StopReason::ExplicitExit).await?;
    Ok(())
}
