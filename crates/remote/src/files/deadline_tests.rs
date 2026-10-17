use super::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn reply() -> NativeFileRead {
    NativeFileRead {
        schema_version: SCHEMA_VERSION,
        connection_generation: 9,
        sequence: 1,
        transfer_id: "00000002-1111-4111-8111-111111111111".into(),
        action: Some(Action::Chunk(FileReadChunk {
            offset: 0,
            data: vec![7; FILE_PAYLOAD_BYTES as usize],
            sha256: vec![1; 32],
        })),
    }
}
#[tokio::test]
async fn synchronous_payload_decode_cannot_escape_the_original_async_deadline() -> Result {
    let bytes = reply().encode_validated()?;
    let deadline = Instant::now() + Duration::from_millis(5);
    // The native timer cannot preempt a synchronous parser on this executor.
    // Use the production decode/consume fence around that delayed operation.
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
        file_operation(deadline, || {
            thread::sleep(Duration::from_millis(15));
            Ok(NativeFileRead::decode_validated(&bytes)?)
        })
    })
    .await;
    assert!(
        matches!(result, Ok(Err(RemoteError::Io(error))) if error.kind() == io::ErrorKind::TimedOut)
    );
    Ok(())
}
#[tokio::test]
async fn completed_worker_reply_is_not_consumed_after_its_original_request_deadline() -> Result {
    let (sent, completed) = oneshot::channel();
    let deadline = Instant::now() + Duration::from_millis(5);
    sent.send(WorkerReply {
        message: reply(),
        disclosure: None,
    })
    .map_err(|_| "reply receiver missing")?;
    thread::sleep(Duration::from_millis(15));
    let completed = completed.await?;
    assert!(
        matches!(file_operation(deadline, || Ok(completed)), Err(RemoteError::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    Ok(())
}
