use super::*;
#[allow(dead_code)]
#[path = "../files/support.rs"]
mod support;
use nestlink_auth::random_id;
use nestlink_identity::digest;
use nestlink_platform_files::download::LocalDownloadSelection;
use nestlink_protocol::{FileReadManifest, NativeFileRead, native_file_read::Action};
use nestlink_transport_stream::Channel;
use std::time::Duration;
use support::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aborted_owned_driver_consumes_source_cleanup_and_explicit_client_retirement_before_release()
-> Result {
    let output = TempDirectory::new()?;
    let area = output.path().join("aborted");
    let (selected, _consent) = LocalDownloadSelection::new(&area, "done", 4)?;
    let mut sessions = Sessions::new(false).await?;
    let queue = NativeDownloadQueue::new(NativeDownloadQueueLimits {
        active: 1,
        tasks: 1,
        reserved_bytes: 4,
    })?;
    let budget = queue.0.0.clone();
    let (signal, _) = watch::channel(false);
    let control = NativeDownloadTaskControl(signal);
    let (progress, _) = watch::channel(NativeDownloadTaskStatus {
        maximum_bytes: 4,
        ..Default::default()
    });
    let task = NativeDownloadTaskMonitor(progress);
    let id = budget.admit(4, control.clone(), task.clone())?;
    let reservation = Reservation {
        id,
        budget,
        task: task.clone(),
        client: Some(FileReadClient::attach(&mut sessions.c, 9)?),
        native: None,
        armed: true,
    };
    let driver = tokio::spawn(run(
        reservation,
        control,
        NativeDownloadRequest::new(&random_id(), "source")?,
        4,
        selected,
    ));
    let frame = tokio::time::timeout(Duration::from_secs(2), sessions.h.receive()).await??;
    let mut reply = NativeFileRead::decode_validated(&frame.payload)?;
    assert!(matches!(reply.action, Some(Action::Open(_))));
    driver.abort();
    assert!(
        driver.await.is_err_and(|error| error.is_cancelled()),
        "aborted driver unexpectedly completed"
    );
    assert_eq!(queue.status().active, 1);
    assert_eq!(queue.status().reserved_bytes, 4);
    assert!(!task.status().finished && !area.exists());
    reply.action = Some(Action::Manifest(FileReadManifest {
        size: 4,
        sha256: digest(b"data").to_vec(),
        offset: 0,
    }));
    sessions
        .h
        .send(Channel::FileRead, &reply.encode_validated()?)
        .await?;
    let frame = tokio::time::timeout(Duration::from_secs(1), sessions.h.receive()).await??;
    let mut reply = NativeFileRead::decode_validated(&frame.payload)?;
    assert_eq!(reply.action, Some(Action::Cancel(true)));
    assert!(
        tokio::time::timeout(Duration::from_millis(40), task.wait_finished())
            .await
            .is_err()
    );
    assert_eq!(queue.status().reserved_bytes, 4);
    reply.action = Some(Action::Cancelled(true));
    sessions
        .h
        .send(Channel::FileRead, &reply.encode_validated()?)
        .await?;
    let actual = tokio::time::timeout(Duration::from_secs(1), task.wait_finished()).await?;
    assert_eq!(actual.error, Some(NativeDownloadQueueError::OwnerEnded));
    assert_eq!(actual.phase, NativeDownloadTaskPhase::Failed);
    assert_eq!(actual.client_retirement, Some(Ok(())));
    let native = actual.native.ok_or("missing finished native status")?;
    assert!(native.actor_finished && native.source_cancel_acknowledged);
    assert_eq!(native.client_retirement, Some(Ok(())));
    assert_eq!(queue.status().tasks, 0);
    assert_eq!(queue.status().active, 0);
    assert_eq!(queue.status().reserved_bytes, 0);
    assert!(!area.exists());
    sessions
        .c
        .lease_control()
        .check_channel_binding(Channel::Video, 9)?;
    Ok(())
}
